from pyquo import session
from pyquo.authenticator import UserAuthenticator
from pyquo.models import Case, File, Encases
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import argparse
import os


class QuoLab(object):

    def __init__(self, url, username, password):
        self.connect(url, username, password)

    def connect(self, url, username, password):
        auth = UserAuthenticator(username=username,
                                 password=password)
        session.Session(base_url=url,
                        global_session=True,
                        auth=auth)


class Watcher(object):

    def __init__(self, case, target):
        self.__case = case
        self.__target = target
        self.__observer = Observer()

    def run(self):
        hdl = Handler(self.__case)
        self.__observer.schedule(hdl, self.__target)
        self.__observer.start()
        print('[+] Now watching "%s"' % (self.__target))
        try:
            while True:
                time.sleep(5)
        except:
            self.__observer.stop()
        self.__observer.join()


class Handler(FileSystemEventHandler):

        def __init__(self, case):
            self.__case = case

        @staticmethod
        def on_any_event(event):
            if event.event_type != 'created':
                return
            with open(event.src_path, 'rb') as f:
                name = os.path.basename(event.src_path)
                print(' |- Uploading "%s"' % (name))
                t = File.upload(f.read(), filename=name)
                t.save()
                ref = Encases(source=case, target=t).save()
                print(' |-- %s' % (ref))


if __name__ == '__main__':
    description = 'Watch a directory and upload new files to a QuoLab case'
    p = argparse.ArgumentParser(description=description)
    p.add_argument('--host', type=str,
                   required=True, help='https://qlab.quo')
    p.add_argument('--creds', type=str,
                   required=True, help='username:password')
    p.add_argument('--caseid', type=str,
                   required=True, help='HPUeI5kDTTyNlWGZbbnQQA')
    p.add_argument('--dir', type=str,
                   required=True, help='target directory')
    args = p.parse_args()

    username, password = args.creds.split(':')
    q = QuoLab(args.host, username, password)

    case = Case(args.caseid)
    case.get()
    print('[+] Target case name is "%s"' % (case.name))

    w = Watcher(case, args.dir)
    w.run()
