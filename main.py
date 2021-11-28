from Crypto.Cipher import AES
import argparse
import hashlib
import sqlite3
import base64
import math
import json


def index_exists(arr, i):
    return (0 <= i < len(arr)) or (-len(arr) <= i < 0)


class KakaoDecrypt:
    @staticmethod
    def gen_salt(user_id):
        incept = 'extr.ursra'
        salt = incept + str(user_id)

        salt = salt[0:16].encode()
        return salt

    @staticmethod
    def pkcs16adjust(a, a_off, b):
        x = (b[len(b) - 1] & 0xff) + (a[a_off + len(b) - 1] & 0xff) + 1
        a[a_off + len(b) - 1] = x % 256
        x = x >> 8
        for i in range(len(b) - 2, -1, -1):
            x = x + (b[i] & 0xff) + (a[a_off + i] & 0xff)
            a[a_off + i] = x % 256
            x = x >> 8

    @staticmethod
    def derive_key(password, salt, iterations, d_key_size):
        password = (password + b'\0').decode('ascii').encode('utf-16-be')

        sha1_hash = hashlib.sha1()
        v = sha1_hash.block_size
        u = sha1_hash.digest_size

        d = [1] * v
        s = [0] * v * int((len(salt) + v - 1) / v)
        for i in range(0, len(s)):
            s[i] = salt[i % len(salt)]
        p = [0] * v * int((len(password) + v - 1) / v)
        for i in range(0, len(p)):
            p[i] = password[i % len(password)]

        sp = s + p

        b = [0] * v
        c = int((d_key_size + u - 1) / u)

        d_key = [0] * d_key_size
        for i in range(1, c + 1):
            sha1_hash = hashlib.sha1()
            sha1_hash.update(bytes(d))
            sha1_hash.update(bytes(sp))
            a = sha1_hash.digest()

            for j in range(1, iterations):
                sha1_hash = hashlib.sha1()
                sha1_hash.update(a)
                a = sha1_hash.digest()

            a = list(a)
            for j in range(0, len(b)):
                b[j] = a[j % len(a)]

            for j in range(0, int(len(sp) / v)):
                KakaoDecrypt.pkcs16adjust(sp, j * v, b)

            start = (i - 1) * u
            if i == c:
                d_key[start: d_key_size] = a[0: d_key_size - start]
            else:
                d_key[start: start + len(a)] = a[0: len(a)]

        return bytes(d_key)

    @staticmethod
    def decrypt(user_id, b64_ciphertext):
        password = b'\x16\x08\x09\x6f\x02\x17\x2b\x08\x21\x21\x0a\x10\x03\x03\x07\x06'
        iv = b'\x0f\x08\x01\x00\x19\x47\x25\xdc\x15\xf5\x17\xe0\xe1\x15\x0c\x35'

        salt = KakaoDecrypt.gen_salt(user_id)
        key = KakaoDecrypt.derive_key(password, salt, 2, 32)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        ciphertext = base64.b64decode(b64_ciphertext)
        padded = cipher.decrypt(ciphertext)
        plaintext = padded[:-padded[-1]]
        return plaintext.decode('UTF-8')


class KakaoDbDecrypter:
    def __init__(self, db_file, db_file2):
        self.friends = {}
        self.en_friends = []
        self.db_file = db_file
        self.db_file2 = db_file2
        self.chat_db = None
        self.friend_db = None
        self.my_id = 0

    def sqlite_connect(self):
        con = sqlite3.connect(self.db_file)
        cur = con.cursor()

        con2 = sqlite3.connect(self.db_file2)
        cur2 = con2.cursor()

        cur.execute("PRAGMA table_info(chat_logs)")
        if len(cur.fetchall()) == 0:
            self.chat_db = cur2
            cur2.execute("PRAGMA table_info(chat_logs)")
            if len(cur2.fetchall()) == 0:
                return "ERROR, chat database required. (KakaoTalk.db)"
        else:
            self.chat_db = cur

        cur.execute("PRAGMA table_info(friends)")
        if len(cur.fetchall()) == 0:
            self.friend_db = cur2
            cur2.execute("PRAGMA table_info(friends)")
            if len(cur2.fetchall()) == 0:
                return "ERROR, friends database required. (KakaoTalk2.db)"
        else:
            self.friend_db = cur

    def find_direct_chat(self, ex_friends):
        print("no".rjust(math.floor(math.log(len(self.en_friends))), " ") + "|친구이름")
        for i in ex_friends:
            print(i)

        print("위의 친구목록중에서 대화목록을 살필 no를 입력해주세요.")
        while True:
            a = input(">>> ")
            if a.isdecimal():
                if index_exists(self.friends, int(a)):
                    break
                else:
                    print("해당 번호의 친구가 존재하지 않습니다.")
            else:
                print("숫자로 입력해주세요.")

        print("")
        self.chat_db.execute("SELECT * FROM 'chat_rooms' WHERE members='[%s]'" % self.en_friends[int(a)][0])
        room = self.chat_db.fetchall()
        print("선택하신 친구의 이름과 해당 채팅방의 마지막 대화가 아래와 같나요?")
        print("친구의 이름: " + KakaoDecrypt.decrypt(self.my_id, self.en_friends[int(a)][1])
              + ", 채팅방의 마지막 대화: " + KakaoDecrypt.decrypt(self.my_id, room[0][6]))
        print("맞다면 y, 다시하려면 n을 입력해주세요.")
        while True:
            answer = input(">>> ")
            if answer == "Y" or answer == "y":
                answer = True
                break
            elif answer == "N" or answer == "n":
                answer = False
                break

        return answer, room[0][1]

    def find_multi_chat(self):
        self.chat_db.execute("SELECT _id, id, members FROM 'chat_rooms' WHERE type='MultiChat'")
        rooms = self.chat_db.fetchall()
        multi_chats = []
        for i, room in enumerate(rooms):
            en_members = []
            try:
                en_members = json.loads(room[2])
            except TypeError:
                print("Warning: skipping row #%d of table %s (invalid json)." % (room[0], "chat_rooms"))
                continue
            multi_chats.append([])
            for member in en_members:
                try:
                    multi_chats[i].append(self.friends[member])
                except KeyError:
                    multi_chats[i].append("친구가 아닌 사람-"+str(member))

        print("no".rjust(math.floor(math.log(len(rooms))), " ") + "|채팅방 인원들")
        for i, chat in enumerate(multi_chats):
            print(str(i) + ": ", end="")
            print(*chat, sep=', ')
            print("")

        print("위의 채팅방목록중에서 대화목록을 살필 no를 입력해주세요.")
        while True:
            a = input(">>> ")
            if a.isdecimal():
                if index_exists(rooms, int(a)):
                    break
                else:
                    print("해당 번호의 채팅방이 존재하지 않습니다.")
            else:
                print("숫자로 입력해주세요.")

        print("")
        self.chat_db.execute("SELECT last_message FROM 'chat_rooms' WHERE id='%s'" % rooms[int(a)][1])
        print("해당 채팅방의 마지막 대화가 아래와 같나요?")
        print("채팅방의 마지막 대화: " + KakaoDecrypt.decrypt(self.my_id, self.chat_db.fetchall()[0][0]))
        print("맞다면 y, 다시하려면 n을 입력해주세요.")
        while True:
            answer = input(">>> ")
            if answer == "Y" or answer == "y":
                answer = True
                break
            elif answer == "N" or answer == "n":
                answer = False
                break

        return answer, rooms[int(a)][1]

    def find_chat(self):
        print("친구와의 개인 채팅을 보려면 d를, 단체방을 살펴보려면 m를 입력해주세요.")
        while True:
            answer = input(">>> ")
            if answer == "D" or answer == "d":
                answer = True
                break
            elif answer == "M" or answer == "m":
                answer = False
                break

        print("")
        if answer:
            ex_friends = []
            for i, friend in enumerate(self.friends.items()):
                ex_friends.append(str(i).rjust(math.floor(math.log(len(self.en_friends))), " ")
                                  + ": " + friend[1])
            friend = False,
            while not friend[0]:
                friend = self.find_direct_chat(ex_friends)
                print("")
            room = friend[1]
        else:
            chat = False,
            while not chat[0]:
                chat = self.find_multi_chat()
                print("")
            room = chat[1]

        return room

    def run(self):
        self.sqlite_connect()

        self.load_database()

        room = self.find_chat()

        self.chat_db.execute("SELECT _id, user_id, message FROM 'chat_logs' WHERE chat_id=%d "
                             "AND not deleted_at = 0 order by created_at" % room)

        deleted = self.chat_db.fetchall()
        deleted_msg = []
        for message in deleted:
            try:
                del_log_id = json.loads(KakaoDecrypt.decrypt(message[1], message[2]))
            except TypeError:
                print("Warning: skipping row #%d of table %s (invalid json)." % (message[0], "chat_logs"))
                continue
            deleted_msg.append(del_log_id["logId"])

        self.chat_db.execute("SELECT id, user_id, message FROM 'chat_logs' WHERE chat_id=%d "
                             "AND attachment not null AND not attachment = '' order by created_at" % room)

        messages = self.chat_db.fetchall()

        self.friends[self.my_id] = "나"

        print("메시지 로그는 아래와 같습니다.")
        print("-----------------------------------------")
        for message in messages:
            deleted = ""
            if message[0] in deleted_msg:
                deleted = "(삭제된 메시지)"
            try:
                print(deleted + self.friends[message[1]] + ": " + KakaoDecrypt.decrypt(message[1], message[2]))
            except KeyError:
                print(deleted + "친구가 아닌 사람-" + str(message[1]) + ": " + KakaoDecrypt.decrypt(message[1], message[2]))
            print("-----------------------------------------")

        return

    def load_database(self):
        # get my id
        # SELECT id FROM 'friends' WHERE not account_id = 0 AND not user_type = 1 AND uuid is null
        #
        # get friends
        # SELECT * FROM 'friends' WHERE uuid not null
        #
        self.friend_db.execute(
            "SELECT id FROM 'friends' WHERE not account_id = 0 AND not user_type = 1 AND uuid is null"
        )
        self.my_id = self.friend_db.fetchall()[0][0]

        self.friend_db.execute(
            "SELECT id, name FROM 'friends' WHERE uuid not null"
        )
        self.en_friends = self.friend_db.fetchall()

        for friend in self.en_friends:
            self.friends[friend[0]] = KakaoDecrypt.decrypt(self.my_id, friend[1])

        print("데이터베이스를 성공적으로 로드하였습니다!")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Decrypt message from database file.')
    parser.add_argument('db_file', help='KakaoTalk.db file')
    parser.add_argument('db_file2', help='KakaoTalk2.db file')
    args = parser.parse_args()

    KakaoDbDecrypter(args.db_file, args.db_file2).run()
