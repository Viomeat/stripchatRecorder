import m3u8
import aiohttp
import json
import logging
import asyncio
import os
import datetime
import re
import aiofiles
import requests
import hashlib
import base64
import threading

# ---------------- 日志系统 ----------------
logger = logging.getLogger("logger")

def setup_logger(log_level="DEBUG", log_dir="logs"):
    os.makedirs(log_dir, exist_ok=True)
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    log_file = os.path.join(log_dir, f"{today}.log")

    logger.handlers.clear()
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # 控制台
    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

    # 文件
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

    logger.addHandler(sh)
    logger.addHandler(fh)

setup_logger()  # 初始化

header = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
}

# ---------------- 工具函数 ----------------
def down_part_url_by_thread(task, url, index):
    try:
        res = requests.get(url, headers=header)
        if res.status_code == 200:
            data_len = len(res.content)
            with task._speed_lock:
                task._downloaded_bytes += data_len
            task.part_down_finish.update({index: res.content})
        else:
            task.part_down_finish.update({index: b""})
            logger.error(f"Download fail: {url} status={res.status_code}")
    except Exception as e:
        task.part_down_finish.update({index: b""})
        logger.error(f"Download error: {url} -> {e}")

def get_psch_pkey_from_m3u8(m3u8_content: str):
    for line in m3u8_content.splitlines():
        if line.startswith('#EXT-X-MOUFLON:PSCH:'):
            parts = line.split(':')
            return parts[2], parts[3]
    return None, None

async def get_decrypt_key(pkey):
    async with aiohttp.ClientSession(trust_env=True, headers=header) as session:
        async with session.get('https://hu.stripchat.com/api/front/v3/config/static') as resp:
            resp = await resp.json()
            static_data = resp.get('static')
            mmp_origin = static_data['features']['MMPExternalSourceOrigin']
            mmp_version = static_data['featuresV2']['playerModuleExternalLoading']['mmpVersion']
            mmp_base = f"{mmp_origin}/v{mmp_version}"
            async with session.get(f"{mmp_base}/main.js") as resp:
                main_js = await resp.text()
                doppio_js = re.findall('require[(]"./(Doppio.*?[.]js)"[)]', main_js)[0]
                async with session.get(f"{mmp_base}/{doppio_js}") as resp:
                    doppio_js = await resp.text()
                    decrypt_key = re.findall(f'"{pkey}:(.*?)"', doppio_js)[0]
                    return decrypt_key

def decode(encrypted_b64: str, key: str) -> str:
    hash_bytes = hashlib.sha256(key.encode("utf-8")).digest()
    encrypted_data = base64.b64decode(encrypted_b64 + "==")
    decrypted_bytes = bytearray()
    for i, cipher_byte in enumerate(encrypted_data):
        key_byte = hash_bytes[i % len(hash_bytes)]
        decrypted_bytes.append(cipher_byte ^ key_byte)
    return decrypted_bytes.decode("utf-8")

def extract_variant_playlists(m3u8_content: str):
    lines = m3u8_content.strip().splitlines()
    result = {}
    current_name = None
    for line in lines:
        line = line.strip()
        if line.startswith("#EXT-X-STREAM-INF:"):
            match = re.search(r'NAME="([^"]+)"', line)
            if match:
                current_name = match.group(1)
        elif line and not line.startswith("#"):
            if current_name:
                result[current_name] = line
                current_name = None
    return result

def extract_mouflon_and_parts(m3u8_content: str):
    lines = m3u8_content.strip().splitlines()
    result = []
    mouflon_value = None
    for line in lines:
        line = line.strip()
        if line.startswith("#EXT-X-MOUFLON:FILE:"):
            mouflon_value = line.split(":", 2)[2]
        elif line.startswith("#EXT-X-PART:") and mouflon_value:
            match = re.search(r'URI="([^"]+)"', line)
            if match:
                part_uri = match.group(1)
                result.append((mouflon_value, part_uri))
            mouflon_value = None
    return result

# ---------------- 异常类 ----------------
class FlagNotSameError(Exception): pass

# ---------------- 主任务逻辑 ----------------
class TaskMixin:
    def __init__(self) -> None:
        self.ext_x_map = None
        self.online_mu3u8_uri = None
        self.current_segment_sequence = 0
        self.stream_name = None
        self.part_to_down = []
        self.part_down_finish = {}
        self.data_map = {}
        self.current_save_path = None
        self.decrypt_key_map = {}
        self.part_index = 0

    async def is_online(self, model_name):
        try:
            async with aiohttp.ClientSession(trust_env=True, headers=header) as session:
                async with session.get(f'https://stripchat.com/api/front/v2/models/username/{model_name}/cam') as resp:
                    resp = await resp.json()
            if 'cam' in resp.keys() and resp['cam'].get('isCamAvailable'):
                stream_name = resp["cam"]["streamName"]
                uri = f'https://edge-hls.doppiocdn.com//hls/{stream_name}/master/{stream_name}_auto.m3u8'
                return uri, stream_name
            return False, None
        except:
            logger.error("Error while checking online", exc_info=True)
            return False, None

    async def get_play_list(self, m3u8_file):
        while True:
            try:
                async with aiohttp.ClientSession(trust_env=True, headers=header) as session:
                    async with session.get(m3u8_file) as resp:
                        res = await resp.text()
                        psch, pkey = get_psch_pkey_from_m3u8(res)
                        variant_playlists = extract_variant_playlists(res)

                        preferred_order = ["1080p", "720p", "480p", "360p", "240p", "source"]
                        media_uri = None
                        selected_quality = None
                        for q in preferred_order:
                            if q in variant_playlists:
                                media_uri = variant_playlists[q]
                                selected_quality = q
                                break
                        if not media_uri and variant_playlists:
                            first_q, first_uri = list(variant_playlists.items())[0]
                            media_uri = first_uri
                            selected_quality = first_q

                        if not psch or not pkey or not media_uri:
                            raise FlagNotSameError

                        if pkey not in self.decrypt_key_map:
                            decrypt_key = await get_decrypt_key(pkey)
                            self.decrypt_key_map[pkey] = decrypt_key
                        else:
                            decrypt_key = self.decrypt_key_map[pkey]

                        media_uri = f"{media_uri}?psch={psch}&pkey={pkey}&playlistType=lowLatency"
                        async with session.get(media_uri) as resp2:
                            res2 = await resp2.text()
                            m3u8_obj = m3u8.loads(res2)
                            self.current_segment_sequence = m3u8_obj.media_sequence
                            self.ext_x_map = m3u8_obj.segments[0].init_section.uri if m3u8_obj.segments else None

                            # ------------------- 只输出一次日志 -------------------
                            if media_uri and selected_quality:
                                if not hasattr(self, "_last_selected_quality"):
                                    self._last_selected_quality = None
                                if self._last_selected_quality != selected_quality:
                                    now_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                    record_dir = self.save_dir
                                    os.makedirs(record_dir, exist_ok=True)
                                    file_name = f"{self.model_name}_{selected_quality}.mp4"
                                    self._current_file = os.path.join(record_dir, file_name)
                                    self._record_start_time = datetime.datetime.now()
                                    logger.info(f"({self.model_name}) Recording started at {now_time} — Quality: {selected_quality} — File: {self._current_file}")
                                    self._last_selected_quality = selected_quality
                            # ------------------------------------------------------------------

                            for mouflon, part in extract_mouflon_and_parts(res2):
                                real_url = decode(mouflon, decrypt_key)
                                real_url = f"{part.rsplit('/',1)[0]}/{real_url}"
                                if real_url not in self.part_to_down:
                                    self.part_to_down.append(real_url)
                                    self.part_index += 1
                                    t = threading.Thread(target=down_part_url_by_thread, args=(self, real_url, self.part_index))
                                    t.start()
                return m3u8_obj
            except Exception as e:
                logger.error(f"({self.model_name}) get m3u8 error -> {e}", exc_info=True)
                self.stop_flag = True
                return self

# ---------------- Task类 ----------------
class Task(TaskMixin):
    def __init__(self, model_name, save_dir):
        self.model_name = model_name
        self.stop_flag = False
        self.has_start = False
        self.save_dir = os.path.join(save_dir, model_name, datetime.datetime.now().strftime("%Y-%m-%d"))
        super().__init__()

        # 下载速度相关
        self._downloaded_bytes = 0
        self._last_bytes = 0
        self._speed = 0.0
        self._speed_lock = threading.Lock()

        self._current_file = None
        self._record_start_time = None

    async def start(self):
        m3u8_uri, stream_name = await self.is_online(self.model_name)
        if not (m3u8_uri and stream_name):
            logger.debug(f"{self.model_name} not online, retry later.")
            self.stop_flag = True
            await asyncio.sleep(2)
            return self

        self.online_mu3u8_uri = m3u8_uri
        self.stream_name = stream_name
        await self.get_play_list(m3u8_uri)

        loop = asyncio.get_event_loop()
        loop.create_task(self.down_init_file()).add_done_callback(self._on_downloader_done)
        loop.create_task(self._start_writer()).add_done_callback(self._on_writer_done)

        while not self.stop_flag:
            self.has_start = True
            await self.get_play_list(self.online_mu3u8_uri)
            await asyncio.sleep(0)
        self.stop_recording()
        return self

    async def down_init_file(self):
        try:
            os.makedirs(self.save_dir, exist_ok=True)
            if self.ext_x_map:
                path = os.path.join(self.save_dir, self.ext_x_map.rsplit('/')[-1])
                self.current_save_path = path
                async with aiohttp.ClientSession(trust_env=True, headers=header) as session:
                    async with session.get(self.ext_x_map) as resp:
                        if resp.status == 200:
                            with open(path, "ab") as f:
                                f.write(await resp.read())
                            logger.info(f"({self.model_name}) Downloaded init file: {path}")
        except:
            logger.error("Error downloading init file", exc_info=True)
            self.stop_flag = True

    async def _start_writer(self):
        index = 1
        while not self.stop_flag:
            if len(self.part_down_finish) > 0:
                if not self.current_save_path:
                    await asyncio.sleep(1)
                    continue
                data = self.part_down_finish.get(index)
                if not data:
                    await asyncio.sleep(1)
                    continue
                if data != b"":
                    async with aiofiles.open(self.current_save_path, 'ab') as afp:
                        await afp.write(data)
                self.part_down_finish.pop(index, None)
                index += 1
            else:
                await asyncio.sleep(1)

    def stop_recording(self):
        if self._record_start_time and self._current_file:
            duration = datetime.datetime.now() - self._record_start_time
            logger.info(f"({self.model_name}) Recording finished. Duration: {str(duration).split('.')[0]} — File: {self._current_file}")

    def _on_downloader_done(self, future):
        error = future.exception()
        if error:
            logger.error(f"({self.model_name}) Downloader error -> {error}", exc_info=True)
        else:
            logger.info(f"({self.model_name}) Downloader done...")

    def _on_writer_done(self, future):
        error = future.exception()
        if error:
            logger.error(f"({self.model_name}) Writer error -> {error}", exc_info=True)
        else:
            logger.info(f"({self.model_name}) Writer done...")

# ---------------- 下载速度统计（单行刷新） ----------------
async def update_speed(task_list: list):
    while True:
        total_speed = 0.0
        output_list = []
        for task in task_list:
            if task.stop_flag:
                continue
            with task._speed_lock:
                speed = (task._downloaded_bytes - task._last_bytes) / 1024 / 1024
                task._speed = speed
                task._last_bytes = task._downloaded_bytes
            total_speed += speed
            output_list.append(f"{task.model_name}: {task._speed:.2f} MB/s")

        if output_list:
            line = " | ".join(output_list) + f" | Total: {total_speed:.2f} MB/s"
            print(f"\r{line}", end="", flush=True)

        await asyncio.sleep(1)

# ---------------- TaskManager ----------------
def get_config(config_file):
    with open(config_file) as f:
        return json.load(f)

class TaskManager:
    def __init__(self, config_file):
        self.config = config_file
        self.task_map = {}

    def add_task(self, task: Task):
        if task.model_name not in self.task_map:
            logger.info(f"({task.model_name}) Start new model task")
            self.task_map[task.model_name] = task
            loop = asyncio.get_event_loop()
            loop.create_task(task.start())

    async def run_forever(self):
        config = get_config(self.config)
        setup_logger(config.get('log', {}).get('level', 'INFO'))
        task_list = []

        if config['proxy']['enable']:
            os.environ['HTTP_PROXY'] = config['proxy']['uri']
            os.environ['HTTPS_PROXY'] = config['proxy']['uri']

        asyncio.create_task(update_speed(task_list))

        while True:
            config = get_config(self.config)
            for model in config['models']:
                task = Task(model['name'], config["save_dir"])
                task_list.append(task)
                self.add_task(task)
            await asyncio.sleep(20)

# ---------------- 启动入口 ----------------
if __name__ == "__main__":
    config_file = "./config.json"
    manager = TaskManager(config_file)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(manager.run_forever())
    loop.close()
