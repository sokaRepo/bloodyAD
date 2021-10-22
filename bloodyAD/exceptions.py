
class BloodyError(Exception):
    pass


class LDAPError(BloodyError):
    pass


class ResultError(LDAPError):

    def __init__(self, result):
        self.result = result

        if self.result['result'] == 50:
            self.message = '[-] Could not modify object, the server reports insufficient rights: ' + self.result['message']
        elif self.result['result'] == 19:
            self.message = '[-] Could not modify object, the server reports a constrained violation: ' + self.result['message']
        else:
            self.message = '[-] The server returned an error: ' + conn.result['message']

        super().__init__(self.message)


class NoResultError(LDAPError):

    def __init__(self, search_base, ldap_filter):
        self.filter = ldap_filter
        self.base = search_base
        self.message = f'[-] No object found in {self.base} with filter: {self.filter}'
        super().__init__(self.message)


class TooManyResultsError(LDAPError):

    def __init__(self, search_base, ldap_filter, entries):
        self.filter = ldap_filter
        self.base = search_base
        self.limit = 10
        self.entries = entries

        if len(self.entries) <= self.limit:
            LOG.error(self.entries)
            self.results = "\n".join(entry['dn'] for entry in entries)
            self.message = f'[-] {len(self.entries)} objects found in {self.base} with filter: {ldap_filter}\n'
            self.message += f'\tPlease put the full target DN\n'
            self.message += f'\tResult of query: \n{self.results}'
        else:
            self.message = f"\tMore than {self.limit} entries in {self.base} match {self.filter}"
            self.message += f'\tPlease put the full target DN'

        super().__init__(self.message)

