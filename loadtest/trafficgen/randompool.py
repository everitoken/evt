import random
import string
import sys
import time

from pysdk import base

ITEM_TYPES = ['domain', 'group', 'fungible', 'token']
REQUIREMENTS = {
    'newdomain': [],
    'updatedomain': ['domain'],
    'newgroup': [],
    'updategroup': ['group'],
    'newfungible': [],
    'updfungible': ['fungible'],
    'issuefungible': ['fungible'],
    'transferft': ['fungible'],
    'issuetoken': ['domain'],
    'transfer': ['token'],
    'addmeta': ['domain|group|token']
}


def fake_name(prefix):
    return prefix + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))


def fake_symbol(prefix):
    prec = random.randint(5, 10)
    prefix = prefix.upper()
    name = ''.join(random.choice(string.ascii_letters[26:]) for _ in range(2))
    return base.Symbol(name=prefix+name, precision=prec)


class Item:
    def __init__(self, name, users):
        self.name = name
        self.users = users
        self.create_time = time.time()

    def pub_keys(self):
        if type(self.users) == list:
            return [str(user.pub_key) for user in self.users]
        else:
            return str(self.users.pub_key)

    def priv_keys(self):
        if type(self.users) == list:
            return [user.priv_key for user in self.users]
        else:
            return [self.users.priv_key]


class Domain(Item):
    def __init__(self, name, user):
        super().__init__(name, user)


class Group(Item):
    def __init__(self, name, user):
        super().__init__(name, user)


class Token(Item):
    def __init__(self, name, user, domain):
        super().__init__(name, user)
        self.domain = domain


class Fungible(Item):
    def __init__(self, sym, user, total_supply):
        super().__init__(sym, user)
        self.total_supply = total_supply
        self.accounts = []


class RandomPool:
    def __init__(self, tg_name, max_user_num=2):
        self.tg_name = tg_name
        self.pool = {}
        for item in ITEM_TYPES:
            self.pool[item] = []
        self.users = [base.User() for _ in range(max_user_num)]

    def satisfy(self, item_type, num=1):
        return len(self.pool[item_type]) >= num

    def satisfy_action(self, action):
        for item in REQUIREMENTS[action]:
            if '|' not in item:
                if self.satisfy(item) == False:
                    return False
            else:
                flag = False
                for each in item.split('|'):
                    flag = flag or self.satisfy(each)
                return flag
        # special cases:
        if action == 'transferft':
            flag = False
            for fung in self.pool['fungible']:
                if len(fung.accounts) > 0:
                    return True
            return flag
        return True

    def add_item(self, item_type, item):
        self.pool[item_type].append(item)

    def get_item(self, item_type):
        return random.choice(self.pool[item_type])

    def pop_item(self, item_type):
        idx = random.randint(0, len(self.pool[item_type])-1)
        return self.pool[item_type].pop(idx)

    def get_user(self):
        return random.choice(self.users)

    def newdomain(self):
        domain = Domain(fake_name(self.tg_name), self.get_user())
        self.add_item('domain', domain)
        return {'name': domain.name, 'creator': domain.pub_keys()}, domain.priv_keys()

    def updatedomain(self):
        pass

    def newgroup(self):
        pass

    def updategroup(self):
        pass

    def newfungible(self):
        sym = fake_symbol(self.tg_name)
        asset = base.new_asset(sym)
        fungible = Fungible(sym, self.get_user(), total_supply=100000)
        self.add_item('fungible', fungible)
        return {'sym': sym, 'creator': fungible.pub_keys(), 'total_supply': asset(100000)}, fungible.priv_keys()

    def updfungible(self):
        pass
        #fungible = self.get_item['fungible']
        # return {'sym':fungible.name, 'issue':None, 'manage':None}

    def issuefungible(self):
        fungible = self.get_item('fungible')
        asset = base.new_asset(fungible.name)
        user = self.get_user()
        fungible.accounts.append(user)
        return {'address': user.pub_key, 'number': asset(1), 'memo': fake_name('memo')}, fungible.priv_keys()

    def transferft(self):
        fungible = None
        random.shuffle(self.pool['fungible'])
        for fung in self.pool['fungible']:
            if len(fung.accounts) > 0:
                fungible = fung
                break
        asset = base.new_asset(fungible.name)
        user1 = random.choice(fungible.accounts)
        user2 = self.get_user()  # not add user2 into accounts for convinient
        return {
            '_from': str(user1.pub_key),
            'to': str(user2.pub_key),
            'number': asset(0.0001),
            'memo': fake_name('memo')
        }, [user1.priv_key]

    def issuetoken(self):
        domain = self.get_item('domain')
        user = self.get_user()
        token = Token(fake_name('token'), user, domain)
        self.add_item('token', token)
        return {
            'domain': domain.name,
            'names': [token.name],
            'owner': [token.pub_keys()]
        }, domain.priv_keys()

    def transfer(self):
        token = self.pop_item('token')
        to_user = self.get_user()

        old_priv = token.priv_keys()
        token.user = to_user
        self.add_item('token', token)

        return {
            'domain': token.domain.name,
            'name': token.name,
            'to': [to_user.pub_key],
            'memo': fake_name('memo')
        }, old_priv

    def addmeta(self):
        item_type = None
        for it in ['domain', 'group', 'token']:
            if len(self.pool[it]) > 0:
                item_type = it if item_type == None else random.choice([
                                                                       item_type, it])
        item = self.get_item(item_type)
        return {
            'meta_key': fake_name('meta.key'),
            'meta_value': fake_name('meta.value'),
            'creator': item.pub_keys(),
            'domain': item_type if item_type != 'token' else item.domain.name,
            'key': item.name
        }, item.priv_keys()

    def require(self, action_type):
        return self.__getattribute__(action_type)()
