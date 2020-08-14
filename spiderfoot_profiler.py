from pyquo import session
from pyquo.authenticator import UserAuthenticator
from pyquo.models import Case, IpAddress, Hostname, AutonomousSystem
from pyquo.models import Encases, ResolvedTo
from pyquo.errors import FetchError
import json
import argparse
import sys

EVENT_TYPES = {
    'BGP_AS_MEMBER': [((IpAddress, 'source_data'),
                       ResolvedTo,
                       (AutonomousSystem, 'data'))],
    'IP_ADDRESS': [((Hostname, 'source_data'),
                    ResolvedTo,
                    (IpAddress, 'data'))],
    'NETBLOCK_MEMBER': [((IpAddress, 'source_data'),
                         ResolvedTo,
                         (IpAddress, 'data'))],
    'PROVIDER_DNS': [((Hostname, 'source_data'),
                      None,
                      (Hostname, 'data'))],
    'PROVIDER_MAIL': [((Hostname, 'source_data'),
                      None,
                      (Hostname, 'data'))]
    }


class QuoLab(object):

    def __init__(self, url, username, password):
        self.connect(url, username, password)

    def connect(self, url, username, password):
        auth = UserAuthenticator(username=username,
                                 password=password)
        session.Session(base_url=url,
                        global_session=True,
                        auth=auth)


class SpiderfootParser(object):

    def __init__(self, report):
        self.__report = report
        self.__folder_ids = {}

    def __lookup_folder(self, case, scan_name, scan_target):
        # If case is set then create and encase a folder, if not create a case
        if case:
            flavor = 'folder'
        else:
            flavor = 'case'
        folder_name = "%s - %s" % (scan_name, scan_target)
        if folder_name in self.__folder_ids:
            folder = Case(self.__folder_ids[folder_name])
            return folder
        folder = Case(name=folder_name, description='Spiderfoot report',
                      flavor=flavor, type='profile').save()
        self.__folder_ids[folder_name] = folder.id
        if case:
            ref = Encases(source=case, target=folder).save()
            print(' |-', ref)
        return folder

    def __fact(self, fact_type, fact_value):
        fact = fact_type(fact_value)
        # Concretize indicators unless phantoms
        if fact_type == IpAddress and '/' in fact_value:
            return fact
        try:
            fact.save()
        except FetchError:
            return None
        return fact

    def __ref(self, ref_type, source, target):
        ref = ref_type(source=source, target=target).save()
        return ref

    def parse_to_case(self, case):
        for e in self.__report:
            if e['event_type'] not in EVENT_TYPES:
                continue
            folder = self.__lookup_folder(case,
                                          e['scan_name'],
                                          e['scan_target'])
            for e_source, ref_type, e_target in EVENT_TYPES[e['event_type']]:
                if e_source:
                    source_type, source_field = e_source
                    source = self.__fact(source_type, e[source_field])
                    if source:
                        ref = self.__ref(Encases, folder, source)
                        print(' |--', ref)

                if e_target:
                    target_type, target_field = e_target
                    target = self.__fact(target_type, e[target_field])
                    if target:
                        ref = self.__ref(Encases, folder, target)
                        print(' |--', ref)

                if ref_type and source and target:
                    ref = self.__ref(ref_type, source, target)
                    print(' |---', ref)


if __name__ == '__main__':
    description = 'Imports Spiderfoot JSON output to QuoLab case'
    p = argparse.ArgumentParser(description=description)
    p.add_argument('--host', type=str,
                   required=True, help='https://qlab.quo')
    p.add_argument('--creds', type=str,
                   required=True, help='username:password')
    p.add_argument('--input', type=str,
                   required=True, help='spiderfoot JSON report')
    p.add_argument('--caseid', type=str, help='example HPUeI5kDTTyNlWGZbbnQQA')
    p.add_argument('--casename', type=str, help='case name to be created')
    args = p.parse_args()

    username, password = args.creds.split(':')
    QuoLab(args.host, username, password)

    if args.caseid and args.casename:
        print('Can\'t have at the same time a case ID and a case name')
        sys.exit(1)
    if args.caseid:
        case = Case(args.caseid)
        case.get()
    if args.casename:
        case = Case(name=args.casename, description='Spiderfoot report',
                    flavor='case', type='profile').save()

    if not args.caseid and not args.casename:
        # A new case will be created for each scan/target
        case = None

    with open(args.input, 'rb') as f:
        p = SpiderfootParser(json.loads(f.read()))
        p.parse_to_case(case)
