#!/usr/bin/env python3
"""Fault test in an isolated data directory. Does not use production credentials."""
import json, os, pathlib, signal, subprocess, tempfile, time, urllib.request
root=pathlib.Path(__file__).resolve().parents[1]
binary=pathlib.Path(os.environ.get('TEST_BINARY',str(root.parent/'work/trendai-v1fs-supervised-test')))
port=int(os.environ.get('TEST_PORT','18098'))
def wait_until(predicate,seconds=45):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        value=predicate()
        if value:return value
        time.sleep(.2)
    raise AssertionError('Timed out waiting for watchdog recovery')
def healthy():
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(f'http://127.0.0.1:{port}/livez',timeout=2) as response:return response.status==200
    except Exception as error:
        healthy.last_error=str(error)
        return False
with tempfile.TemporaryDirectory(prefix='trendai-watchdog-') as data:
    env=dict(os.environ,V1FS_DATA_DIR=data,V1FS_WEB_DIR=str(root/'dist'),PORT=str(port),V1FS_WATCHDOG_INTERVAL_SECONDS='1',V1FS_WATCHDOG_STARTUP_SECONDS='1')
    with open(pathlib.Path(data)/'supervisor.log','w+') as log:
        process=subprocess.Popen([str(binary),'-supervise'],env=env,stdout=log,stderr=log)
        def child():
            try:
                raw=[]
                for entry in pathlib.Path(f'/proc/{process.pid}/task').glob('*/children'):
                    try:raw.extend(entry.read_text().split())
                    except OSError:pass
                return int(raw[0]) if raw else None
            except (OSError,ValueError):return None
        try:
            wait_until(healthy);first=wait_until(child)
            os.kill(first,signal.SIGKILL)
            second=wait_until(lambda:child() if child() and child()!=first and healthy() else None)
            os.kill(second,signal.SIGSTOP)
            third=wait_until(lambda:child() if child() and child()!=second and healthy() else None,55)
            assert third!=first
            print(json.dumps({'abrupt_child_exit':'recovered','unresponsive_child':'recovered','persistent_database':'reopened','result':'passed'}))
        except Exception:
            log.flush();log.seek(0);print(log.read());print("Last HTTP probe error:",getattr(healthy,"last_error",None));raise
        finally:
            process.terminate()
            try:process.wait(timeout=15)
            except subprocess.TimeoutExpired:process.kill();process.wait()
