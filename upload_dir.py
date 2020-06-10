from pyquo import session
from pyquo.authenticator import UserAuthenticator
from pyquo.models import Case, File, Encases
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


if __name__ == '__main__':
    description = 'Upload content of a directory to a QuoLab case'
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

    for (dirpath, dirnames, filenames) in os.walk(args.dir):
        for name in filenames:
            with open(os.path.join(dirpath, name), 'rb') as f:
                print(' |- Uploading "%s"' % (name))
                t = File.upload(f.read(), filename=name)
                t.save()
                ref = Encases(source=case, target=t).save()
                print(' |-- %s' % (ref))
