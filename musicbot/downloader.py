import os
import re
import asyncio
import logging
import functools
from concurrent.futures import ThreadPoolExecutor

import youtube_dl

log = logging.getLogger(__name__)

ytdl_format_options = {
    'format': 'bestaudio/best',
    'outtmpl': '%(extractor)s-%(id)s-%(title)s.%(ext)s',
    'restrictfilenames': True,
    'noplaylist': True,
    'nocheckcertificate': True,
    'ignoreerrors': False,
    'logtostderr': False,
    'quiet': True,
    'no_warnings': True,
    'default_search': 'auto',
    'source_address': '0.0.0.0',
    'usenetrc': True
}

# Fuck your useless bugreports message that gets two link embeds and confuses users
youtube_dl.utils.bug_reports_message = lambda: ''

'''
    Alright, here's the problem.  To catch youtube-dl errors for their useful information, I have to
    catch the exceptions with `ignoreerrors` off.  To not break when ytdl hits a dumb video
    (rental videos, etc), I have to have `ignoreerrors` on.  I can change these whenever, but with async
    that's bad.  So I need multiple ytdl objects.

'''

class Downloader:
    def __init__(self, download_folder=None):
        self.thread_pool = ThreadPoolExecutor(max_workers=2)
        self.unsafe_ytdl = youtube_dl.YoutubeDL(ytdl_format_options)
        self.safe_ytdl = youtube_dl.YoutubeDL(ytdl_format_options)
        self.safe_ytdl.params['ignoreerrors'] = True
        self.download_folder = download_folder
        self.gdrive = None

        if download_folder:
            otmpl = self.unsafe_ytdl.params['outtmpl']
            self.unsafe_ytdl.params['outtmpl'] = os.path.join(download_folder, otmpl)
            # print("setting template to " + os.path.join(download_folder, otmpl))

            otmpl = self.safe_ytdl.params['outtmpl']
            self.safe_ytdl.params['outtmpl'] = os.path.join(download_folder, otmpl)


    @property
    def ytdl(self):
        return self.safe_ytdl

    async def extract_info(self, loop, song_url, *args, on_error=None, retry_on_error=False, **kwargs):
        """
            Runs ytdl.extract_info within the threadpool. Returns a future that will fire when it's done.
            If `on_error` is passed and an exception is raised, the exception will be caught and passed to
            on_error as an argument.
        """
        drive = False
        if re.match(
            r"https:\/\/drive\.google\.com\/(drive\/folders\/|open\?id=|drive\/u\/1\/folders\/|file\/d\/|open\?id=|drive\/u\/1\/folders\/)([\da-zA-Z-_]+)",
            song_url
        ):
            drive = True
            song_url = re.match(
                r"https:\/\/drive\.google\.com\/(drive\/folders\/|open\?id=|drive\/u\/1\/folders\/|file\/d\/|open\?id=|drive\/u\/1\/folders\/)([\da-zA-Z-_]+)",
                song_url
            ).group(2)

        if not drive:
            if callable(on_error):
                try:
                    return await loop.run_in_executor(self.thread_pool, functools.partial(self.unsafe_ytdl.extract_info, song_url, *args, **kwargs))

                except Exception as e:

                    # (youtube_dl.utils.ExtractorError, youtube_dl.utils.DownloadError)
                    # I hope I don't have to deal with ContentTooShortError's
                    if asyncio.iscoroutinefunction(on_error):
                        asyncio.ensure_future(on_error(e), loop=loop)

                    elif asyncio.iscoroutine(on_error):
                        asyncio.ensure_future(on_error, loop=loop)

                    else:
                        loop.call_soon_threadsafe(on_error, e)

                    if retry_on_error:
                        return await self.safe_extract_info(loop, song_url, *args, **kwargs)
            else:
                return await loop.run_in_executor(self.thread_pool, functools.partial(self.unsafe_ytdl.extract_info, song_url, *args, **kwargs))
        else:
            if kwargs['download']:
                res = await loop.run_in_executor(self.thread_pool, functools.partial(self.gdrive.download_file, song_url, *args, **kwargs))
                await asyncio.sleep(2)
            else:
                res = await loop.run_in_executor(self.thread_pool, functools.partial(self.gdrive.get_info, song_url, *args, **kwargs))
            return await res


    async def safe_extract_info(self, loop, song_url, *args, **kwargs):
        return await loop.run_in_executor(self.thread_pool, functools.partial(self.safe_ytdl.extract_info, song_url, *args, **kwargs))
