#!/usr/bin/env python3

import os
import pathlib
import json
import subprocess
import multiprocessing


challenges = [
    'YAN01_00015',
    'YAN01_00016',
    'CROMU_00046',
    'CROMU_00047',
    'CROMU_00048',
    'CROMU_00051',
    'CROMU_00054',
    'CROMU_00055',
    'CROMU_00057',
    'CROMU_00058',
    'CROMU_00061',
    'CROMU_00063',
    'CROMU_00064',
    'CROMU_00065',
    'CROMU_00066',
    'CROMU_00072',
    'CROMU_00073',
    'CROMU_00076',
    'CROMU_00077',
    'CROMU_00078',
    'CROMU_00079',
    'CROMU_00082',
    'CROMU_00083',
    'CROMU_00084',
    'CROMU_00087',
    'CROMU_00088',
    'CROMU_00092',
    'CROMU_00093',
    'CROMU_00094',
    'CROMU_00095',
    'CROMU_00096',
    'CROMU_00097',
    'CROMU_00098',
    'KPRCA_00062',
    'KPRCA_00064',
    'KPRCA_00065',
    'KPRCA_00068',
    'KPRCA_00069',
    'KPRCA_00071',
    'KPRCA_00073',
    'KPRCA_00074',
    'KPRCA_00075',
    'KPRCA_00077',
    'KPRCA_00079',
    'KPRCA_00081',
    'KPRCA_00086',
    'KPRCA_00087',
    'KPRCA_00088',
    'KPRCA_00091',
    'KPRCA_00093',
    'KPRCA_00094',
    'KPRCA_00097',
    'KPRCA_00099',
    'KPRCA_00100',
    'KPRCA_00101',
    'KPRCA_00102',
    'KPRCA_00110',
    'KPRCA_00111',
    'KPRCA_00112',
    'KPRCA_00119',
    'KPRCA_00120',
    'NRFIN_00043',
    'NRFIN_00044',
    'NRFIN_00045',
    'NRFIN_00046',
    'NRFIN_00049',
    'NRFIN_00051',
    'NRFIN_00052',
    'NRFIN_00053',
    'NRFIN_00054',
    'NRFIN_00055',
    'NRFIN_00056',
    'NRFIN_00059',
    'NRFIN_00061',
    'NRFIN_00063',
    'NRFIN_00064',
    'NRFIN_00065',
    'NRFIN_00066',
    'NRFIN_00067',
    'NRFIN_00069',
    # 'NRFIN_00071',
    'NRFIN_00072',
]


def pov_type(pov_path):
    child_conn, parent_conn = multiprocessing.Pipe(duplex=True)

    def dup_child_3():
        os.dup2(child_conn.fileno(), 3, inheritable=True)

    pov_popen = subprocess.Popen(['qemu-cgc/i386-linux-user/qemu-i386', pov_path],
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 pass_fds=(3,),
                                 preexec_fn=dup_child_3)

    pov_type = int.from_bytes(os.read(parent_conn.fileno(), 4), 'little')
    pov_popen.kill()
    return pov_type


def challenge_paths(challenge):
    corpus = pathlib.Path('cgc-challenge-corpus')
    target = corpus / challenge / 'bin' / challenge
    pov = corpus / challenge / 'pov'
    if not target.exists():
        # print(f'`{challenge}` target could not be located')
        return
    elif not pov.exists():
        # print(f'`{challenge}` pov could not be located')
        return
    if pov.is_dir():
        for pov in pov.glob('*.pov'):
            yield pov, target
    else:
        yield pov, target


def work(challenge, pov_path, target_path):
    result = {}

    type_ = pov_type(pov_path)

    if type_ == 2:
        print(f'Attempting `{challenge}`: {pov_path.name} (type {type_})')

        try:
            proc = subprocess.run(['./run.py', pov_path, target_path],
                                  capture_output=True,
                                  timeout=60)
            result = json.loads(proc.stdout)
        except subprocess.TimeoutExpired as e:
            result['error'] = str(e)

    return result

def main():
    results = pathlib.Path('/results')

    failed = 0
    total = 0

    for challenge in challenges:
        for pov_path, target_path in challenge_paths(challenge):
            result = work(challenge, pov_path, target_path)
            if not result:
                continue
            error = result.get('error')
            if error:
                print(f'Error: {error}')
                failed += 1
            else:
                success = result['pov_answer_correct']
                if not success:
                    failed += 1
                print(f'Success: {success}')
            with open(results / f'{challenge}_{pov_path.name}', 'w') as f:
                json.dump(result, f, indent=4)
            total += 1

    passed = total - failed
    print(f'Summary: {passed}/{total} passed')
    exit(failed)


if __name__ == '__main__':
    main()
