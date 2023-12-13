#  Copyright Control-F 2020-2024
#
#  This software is licensed 'as-is'.  You bear the risk of using it.  In
#  consideration for use of the software, you agree that you have not relied upon
#  any, and we have made no, warranties, whether oral, written, or implied, to
#  you in relation to the software.  To the extent permitted at law, we disclaim
#  any and all warranties, whether express, implied, or statutory, including, but
#  without limitation, implied warranties of non-infringement of third party
#  rights, merchantability and fitness for purpose.
#
#  In no event will we be held liable to you for any loss or damage (including
#  without limitation loss of profits or any indirect or consequential losses)
#  arising from the use of this software.
#
#  Permission is granted to anyone to use this software free of charge for any
#  purpose, including commercial applications, and to alter it and redistribute
#  it freely, subject to the following restrictions:
#
#  1. The origin of this software must not be misrepresented; you must not
#  claim that you wrote the original software. If you use this software
#  in a product, an acknowledgment in the form of
#  "Copyright Control-F 2024" in the product
#  documentation would be appreciated but is not required.
#
#  2. Altered versions of the source code must be plainly marked as such, and
#  must not be misrepresented as being the original software.
#
#  3. This copyright notice and disclaimer may not be removed from or varied in
#  any copy of the software (whether in its original form or any altered version)
#
#  AUTHORS:
#    Mike Bangham (Control-F www.controlf.net)
#
#  REQUIREMENTS:
#    Python 3
#
#  A script to brute force Huawei App Lock encryption to recover the PIN or recovery passphrase/password

import hashlib
import random
from os.path import join as pj
from os.path import dirname, basename, isfile, abspath
from binascii import hexlify
import sys
import argparse
import zipfile
import sqlite3
from io import BytesIO

__version__ = 0.03
__description__ = 'Huawei App Lock Bruteforcer'
__author__ = 'mike.bangham@controlf.co.uk'


def derive_hash(candidate, salt):
    # pad the candidate, then salt by prepending it to the integer salt. Then encode as bytes
    encoded_salted_pin = str('{}{}'.format(candidate, salt)).encode()
    # Generate a sha256 hash of the encoded salted PIN.
    return (hashlib.sha256(encoded_salted_pin)).hexdigest()


def derive_key(hash, iters, master_key, encoding='utf-8', alg='sha1'):
    # generate the derived key using PBKDF2 (sha1), the encoded sha256 hash of the salted pword
    # and the master key with 1000 rounds/iterations
    return hashlib.pbkdf2_hmac(alg, hash.encode(encoding), bytes.fromhex(master_key), int(iters))


def progress(c):  # c is the percentage completed (integer)
    sys.stdout.write('\r')  # allows us to flush the terminal and '\r' (return) to the beginning of the line
    sys.stdout.write("[%-100s] %d%%" % ('=' * c, c))
    sys.stdout.flush()


def bruteforcer(params_dict, attack_type, wordlist=None):
    count = 0
    if attack_type == 'pin':
        print('Bruteforcing PIN. 0-999999 (1000000 candidates)...')
        while count < 1000000:  # total number of PIN candidates is 999999
            padded_pin = f'{count:06}'  # # pad count to make 6 digit PIN
            _hash = derive_hash(padded_pin, params_dict['salt'])
            derived_key = derive_key(_hash, params_dict['iters'], params_dict['master_key'])
            # check if the derived_key matches the first 24 chars of the stored hash
            if hexlify(derived_key).decode()[:24].lower() in params_dict['match'].lower():
                return ['Cracked',
                        'PIN: {}'.format(padded_pin),
                        'Derived Key: {}'.format(hexlify(derived_key).decode())]  # return PIN and derived key
            progress(round((count / 999999) * 100))
            count += 1
        return False
    else:
        print('\n[!] PIN bruteforce failed'
              '\nAttempting password recovery'
              '\nWordlist: {}'
              '\nCandidates: {}\n'.format(wordlist[0], wordlist[1]))
        with open(wordlist[0], 'r') as wf:
            for word in wf:
                _hash = derive_hash(word, params_dict['salt'])  # salt our word
                derived_key = derive_key(_hash, params_dict['iters'], params_dict['master_key'])
                # check if the derived_key matches the first 24 chars of the stored hash
                if hexlify(derived_key).decode()[:24].lower() in params_dict['match'].lower():
                    return ['Cracked',
                            'Password: {}'.format(word),
                            'Derived Key: {}'.format(hexlify(derived_key).decode())]  # return password and derived key
                progress(round((count / wordlist[1]) * 100))
                count += 1
        return False


def fetch_params(input_file):
    db_out_fn = pj(dirname(input_file), 'applock.db')
    with zipfile.ZipFile(input_file, 'r') as zip_obj:
        app_lock_db = [f.filename for f in zip_obj.infolist() if 'applock.db' in f.filename.lower()]
        if app_lock_db:
            print('[*] Found applock.db!\n')
            with open(db_out_fn, 'wb') as file_out:
                f = zip_obj.read(app_lock_db[0])
                file_out.write(f)
        else:
            return False

    conn = sqlite3.connect(db_out_fn)
    cursor = conn.cursor()
    cursor.execute("""SELECT * FROM applockpreference""")
    params_dict = dict()
    for row in cursor.fetchall():
        if 'app_lock_func_status' in row:
            params_dict['status'] = row[2]
        if 'encrypt_password_sha256_salt' in row or 'encrypt_password_pin6_sha256_salt' in row:
            params_dict['salt'] = row[2]
        if 'encrypt_password_sha256' in row or 'encrypt_password_pin6_sha256' in row:
            args_ = row[2].split(':')
            params_dict['iters'] = args_[0]
            params_dict['master_key'] = args_[1]
            params_dict['match'] = args_[2]
    return params_dict


if __name__ == '__main__':
    print("\n\n"
          "                                                        ,%&&,\n"
          "                                                    *&&&&&&&&,\n"
          "                                                  /&&&&&&&&&&&&&\n"
          "                                               #&&&&&&&&&&&&&&&&&&\n"
          "                                           ,%&&&&&&&&&&&&&&&&&&&&&&&\n"
          "                                        ,%&&&&&&&&&&&&&&#  %&&&&&&&&&&,\n"
          "                                     *%&&&&&&&&&&&&&&%       %&&&&&&&&&%,\n"
          "                                   (%&&&&&&&&&&&&&&&&&&&#       %&%&&&&&&&%\n"
          "                               (&&&&&&&&&&&&&&&%&&&&&&&&&(       &&&&&&&&&&%\n"
          "              ,/#%&&&&&&&#(*#&&&&&&&&&&&&&&%,    #&&&&&&&&&(       &&&&&&&\n"
          "          (&&&&&&&&&&&&&&&&&&&&&&&&&&&&&#          %&&&&&&&&&(       %/\n"
          "       (&&&&&&&&&&&&&&&&&&&&&&&&&&&&&(               %&&&&&&&&&/\n"
          "     /&&&&&&&&&&&&&&&&&&%&&&&&&&%&/                    %&&&&&,\n"
          "    #&&&&&&&&&&#          (&&&%*                         #,\n"
          "   #&&&&&&&&&%\n"
          "   &&&&&&&&&&\n"
          "  ,&&&&&&&&&&\n"
          "   %&&&&&&&&&                           {}\n"
          "   (&&&&&&&&&&,             /*          Version: {}\n"             
          "    (&&&&&&&&&&&/        *%&&&&&#\n"
          "      &&&&&&&&&&&&&&&&&&&&&&&&&&&&&%\n"
          "        &&&&&&&&&&&&&&&&&&&&&&&&&%\n"
          "          *%&&&&&&&&&&&&&&&&&&#,\n"
          "                *(######/,".format(__description__, __version__))
    print('\n\n')

    print("Append the '--help' command to see usage in detail")
    parser = argparse.ArgumentParser(description=__description__)
    parser.add_argument('-i', required=True, type=str, help='Path to Huawei File System zip archive (>= EMUI 8)')
    parser.add_argument('-w', required=False, type=str, help=' Optional: Path to newline separated wordlist file')
    args = parser.parse_args()

    if len(args.i) and isfile(abspath(args.i)):
        _input = abspath(args.i)
    else:
        print('[!!] Error: Please provide a zip archive for argument -i')
        sys.exit()

    wordlist = list()
    try:
        if isfile(abspath(args.w)):
            wordlist.append(abspath(args.w))
            total_words = sum(1 for line in open(wordlist[0]))
            if not total_words:
                raise IndexError
            else:
                wordlist.append(total_words)
    except:
        print('\n[-] Wordlist (-w) not specified or the file is not valid. '
              '\nIf a wordlist was specified, please ensure words must be separated by newlines.'
              '\nOnly PIN combinations will be attacked.\n')

    params_dict = fetch_params(_input)
    if params_dict:
        if params_dict['status'] == 'true':
            print('\n------ Encryption Parameters ------\n')
            print('Salt: {}'.format(params_dict['salt']))
            print('Iterations: {}'.format(params_dict['iters']))
            print('Master Key: {}'.format(params_dict['master_key']))
            print('\n\n')
            out = bruteforcer(params_dict, 'pin')
            if not out and wordlist:
                out = bruteforcer(params_dict, 'pword', wordlist=wordlist)
            elif not out and not wordlist:
                print('PIN bruteforce failed :(. It might be a password.\n'
                      'Try submitting a wordlist to this function using the -w argument')
            if out[0] == 'Cracked':
                print('\n')
                for o in out:
                    print('\n[*] {}'.format(o))
            print('\nFinished!\n')

        else:
            print("Huawei Applock is not enabled on this device. Status is set to 'false'")
            sys.exit()
    else:
        print('[!!] Error - the archive provided does not contain applock.db')
        sys.exit()
