import json
import requests
import pickle
import zlib

from jwcrypto.jws import JWS, JWK, InvalidJWSOperation
from requests.exceptions import ConnectionError

class SmartHealthVerifier:
    # keys can be specified as (issuer, jsonkey) tuples
    def __init__(self, keyset=None, loadissuers=False):
        self.keys = {}
        self.issuers = {}
        # contains {iss: name} mappings for issuers that have been imported
        # other issuers linked in a card can be requested automatically,
        # but usually should not be trusted
        self.trustedissuers = {}
        self.issuerscached = False
        
        # FIXME: allow setting custom cache files?
        if loadissuers:
            try:
                with open("keycache.pickle", "rb") as f:
                    self.keys = pickle.load(f)
                with open("issuercache.pickle", "rb") as f:
                    self.issuers = pickle.load(f)
                with open("namecache.pickle", "rb") as f:
                    self.trustedissuers = pickle.load(f)
                self.issuerscached = True
            except OSError:
                self.keys = {}
                self.issuers = {}
                self.trustedissuers = {}

        if keyset:
            for issuer, jsonkey in keyset:
                self.addkey(jsonkey, issuer)

    def addkey(self, keydata, issuer=None):
        jwk = JWK(**keydata)
        # check that the SHA-256 thumbprint matches the kid provided
        kid = keydata["kid"]
        if not kid == jwk.thumbprint():
            raise ValueError("Provided key has an incorrect kid value.")
        self.keys[kid] = jwk
        if issuer:
            self.issuers[kid] = issuer
        return kid

    def addissuer(self, issuer, issuername):
        self.trustedissuers[issuer] = issuername

    def syncissuers_json(self, issuersjson, save=True, debug=False):
        j = json.loads(issuersjson)
        issuers = j["participating_issuers"]
        for issuer in issuers:
            iss = issuer["iss"]
            name = issuer["name"]
            self.addissuer(iss, name)
            if debug:
                print("Requesting keys from", name, iss)
            keys = self.requestkeys(iss)
            for key in keys:
                self.addkey(key, iss)

        if save:
            with open("keycache.pickle", "wb") as f:
                pickle.dump(self.keys, f)
            with open("issuercache.pickle", "wb") as f:
                pickle.dump(self.issuers, f)
            with open("namecache.pickle", "wb") as f:
                pickle.dump(self.trustedissuers, f)

    def syncissuers_url(self, issuers_url, save=True, debug=False):
        req = requests.get(issuers_url, timeout=30)
        if not req.ok:
            print(f"Requesting provided URL failed for reason {req.reason}.")
            return
        self.syncissuers_json(req.content, save, debug)

    def verifysignature(self, jws, kid=None, checkallkeys=False):
        if not kid:
            header = json.loads(jws.objects["protected"])
            kid = header["kid"]
        verified = False
        if kid in self.keys:
            try:
                jws.verify(self.keys[kid])
                verified = True
            except InvalidJWSOperation:
                pass
        if not verified and checkallkeys:
            for key in self.keys.values():
                try:
                    jws.verify(key)
                    verified = True
                except InvalidJWSOperation:
                    pass
                if verified:
                    break
        return verified

    def requestkeys(self, issuer_url):
        # we don't care about specific exception types
        # if the issuer's key server is broken, it's just broken
        try:
            req = requests.get(issuer_url + "/.well-known/jwks.json", timeout=10)
            if req.status_code != 200:
                print(f"Requesting provided URL failed for reason {req.reason}.")
                return []
            return json.loads(req.content)["keys"]
        except Exception:
            pass
        return []

    def decode_qr(self, qr_string, use_remote=False):
        qr_string = qr_string.removeprefix("shc:/")
        jws_str = ""
        for p, q in zip(qr_string[0::2], qr_string[1::2]):
            jws_str += chr(int(p + q) + 45)
       
        jws = JWS()
        jws.deserialize(jws_str)
        rawdata = jws.objects["payload"]

        # thanks to marcan2020 for pointing out how to do this
        # https://marcan2020.medium.com/reversing-smart-health-cards-e765157fae9
        data = zlib.decompress(rawdata, wbits=-15)
        issuer = json.loads(data)["iss"]
        if not self.verifysignature(jws):
            # check for issuer not in public database
            if use_remote:
                remote_keys = self.requestkeys(issuer)
                for key in remote_keys:
                    # note: we add the key to our library for easily availability
                    # but we are not trusting it; make sure to check trustedissuers
                    self.addkey(key)
                if not self.verifysignature(jws):
                    raise ValueError("Invalid signature provided.")
            else:
                raise ValueError("Invalid signature provided.")

        return json.loads(data)

    # some large records have to be broken into multiple qr codes,
    # which can scan in any order, and must be assembled to verify
    # FIXME: haven't really tested this mode
    def decode_multi_qr(self, qr_string_list, use_remote=False):
        ordered_qr_string_list = []
        for qr_string in qr_string_list:
            if not qr_string.startswith("shc:/"):
                raise ValueError("Provided QR code did not begin with shc:/")
            qr_string = qr_string.removeprefix("shc:/")
            parts = qr_string.partition("/")
            # this qr is the qr_index entry in the sequence
            qr_index = int(parts[0])
            parts = parts[2].partition("/")
            # the sequence contains qr_count qr codes
            qr_count = int(parts[0])
            qr_data = parts[2]

            # verify that qr_count matches what we actually have
            if not qr_count == len(qr_string_list):
                raise ValueError(f"{qr_count} QR codes are specified internally, but {len(qr_string_list)} codes were provided.")

            ordered_qr_string_list.append((qr_index, qr_data))

        # put the parts together in the right order
        ordered_qr_string_list.sort(key=lambda x: x[0])
        raw_qr_string = "".join([x[1] for x in ordered_qr_string_list])

        # verify using the single qr decoder, and return
        return decode_qr(raw_qr_string, use_remote)


# just an example, for anyone not using this as a library
# adds keys from a public directory of reputable issuers
# verifies a qr (data provided in stdin) against this key
if __name__ == "__main__":
    SMV = SmartHealthVerifier(loadissuers=True)
    if not SMV.issuerscached:
        SMV.syncissuers_url("https://raw.githubusercontent.com/the-commons-project/vci-directory/main/vci-issuers.json", debug=True)

    # get qr
    qr_data = input().strip()

    # verify and print data
    j = SMV.decode_qr(qr_data, use_remote=True)
    print(json.dumps(j, indent=2))
    if j["iss"] in SMV.trustedissuers:
        print("Issued by", SMV.trustedissuers[j["iss"]])
    else:
        print("UNKNOWN ISSUER:", j["iss"])
