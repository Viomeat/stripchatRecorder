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
from typing import List, Dict
import threading

# 初始化日志对象
logger = logging.getLogger('logger')

header = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
}

# ---------------- 日志系统 ----------------
def setup_logger(log_level='DEBUG'):
    level_map = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR
    }

    logger.handlers.clear()
    logger.setLevel(level_map.get(log_level.upper(), logging.INFO))

    # 控制台输出
    sh = logging.StreamHandler()
    sh.setLevel(level_map.get(log_level.upper(), logging.INFO))
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    sh.setFormatter(formatter)

    # 文件日志输出
    fh = logging.FileHandler("./err_record.log", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)

    logger.addHandler(sh)
    logger.addHandler(fh)

    return logger

# ---------------- 工具函数 ----------------
def down_part_url_by_thread(task, url, index):
    res = requests.get(url, headers=header)
    if res.status_code == 200:
        logger.debug(f"Download success: {url} index={index}")
        task.part_down_finish.update({index: res.content})
    else:
        logger.error(f"Download fail: {url} status={res.status_code}")
        task.part_down_finish.update({index: b""})

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

def extract_variant_playlists(m3u8_content: str) -> Dict[str, str]:
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

def extract_mouflon_and_parts(m3u8_content: str) -> List[Dict[str, str]]:
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
class TaskFinishError(Exception): pass
class ModelOfflineError(Exception): pass

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
            if 'cam' in resp.keys():
                if resp['cam'].get('isCamAvailable'):
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

                        # ✅ 自动选择最高画质
                        preferred_order = ["1080p", "720p", "480p", "360p", "240p", "source"]
                        media_uri = None
                        for q in preferred_order:
                            if q in variant_playlists:
                                media_uri = variant_playlists[q]
                                logger.info(f"({self.model_name}) Selected best stream quality: {q}")
                                break
                        if not media_uri and variant_playlists:
                            first_q, first_uri = list(variant_playlists.items())[0]
                            media_uri = first_uri
                            logger.warning(f"({self.model_name}) fallback to {first_q}")

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
                            self.ext_x_map = m3u8_obj.segments[0].init_section.uri
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
                    await asyncio.sleep(5)
                    continue
                data = self.part_down_finish.get(index)
                if not data:
                    await asyncio.sleep(5)
                    continue
                if data != b"":
                    async with aiofiles.open(self.current_save_path, 'ab') as afp:
                        await afp.write(data)
                self.part_down_finish.pop(index, None)
                index += 1
            else:
                await asyncio.sleep(5)

    # ✅ 回调函数恢复
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

# ---------------- 管理器 ----------------
def get_config(config_file):
    with open(config_file) as f:
        return json.load(f)

class TaskManager:
    task_map = {}
    def __init__(self, config_file):
        self.config = config_file

    def add_task(self, task: Task):
        if task.model_name not in self.task_map:
            logger.info(f"({task.model_name}) Start new model task")
            self.task_map[task.model_name] = task
            loop = asyncio.get_event_loop()
            loop.create_task(task.start()).add_done_callback(self.on_task_done)

    async def run_forever(self):
        config = get_config(self.config)
        setup_logger(config.get('log', {}).get('level', 'INFO'))
        if config['proxy']['enable']:
            os.environ['HTTP_PROXY'] = config['proxy']['uri']
            os.environ['HTTPS_PROXY'] = config['proxy']['uri']
        while True:
            config = get_config(self.config)
            for model in config['models']:
                task = Task(model['name'], config["save_dir"])
                self.add_task(task)
            await asyncio.sleep(20)

    def on_task_done(self, future):
        t: Task = future.result()
        self.task_map.pop(t.model_name, None)
        logger.info(f"({t.model_name}) task done")

# ---------------- 启动入口 ----------------
if __name__ == "__main__":
    config_file = "./config.json"
    manager = TaskManager(config_file)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(manager.run_forever())
    loop.close()
