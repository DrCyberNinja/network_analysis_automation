###################################################
######  Automated PCAP Analysis Using  ############
######  Bro/Zeek, Virus Total, Hybrid Analysis  ###
######        DrCyberNinja          ###############
###################################################

 #pulling files from Bro output into a directory dir_name and passing it to function get_files
import glob
import os
import requests
from os.path import abspath, basename
from argparse_prompt import PromptParser



def get_files(dir_name):
    brofiles = []
    for file in glob.glob("{}/*._xe".format(dir_name)):
        brofiles.append(file)
    return brofiles


# run Linux command for Bro in Python3 and create Bro script to extract files and then clean up bro file to not clog directory
def run_bro(pcap_file):
    data = """ event file_sniff(f: fa_file, meta: fa_metadata)
    {
    if ( ! meta?$mime_type ) return;
    if ( meta$mime_type == "application/x-dosexec" )
        {
        local fname = fmt("%s-%s.%s", f$source, f$id, "_xe");
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
        }
    }"""
    with open('extract_exe.bro', 'w') as bro_script:
        bro_script.write(data)
    os.system('zeek -C -r {} extract_exe.bro'.format(pcap_file))
    os.remove('extract_exe.bro')


#Utilize requests to check executables in VirusTotal with API
def scan_file(file):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    files = {"file": (basename(file), open(abspath(file), "rb"))}
    params = {'apikey': 'Your_VT_Key'}

    vt_req = requests.post(url, files=files, params=params)

    if vt_req.status_code == 200:
        print(vt_req.json()['permalink'])
    elif vt_req.status_code == 204:
        print('You are over your rate limit.')
    else:
        print('Error with submission')
        print('Status Code: {}'.format(vt_req.status_code))
        print('Msg: {}'.format(vt_req.text))


#Take PE file and run in Hybrid-Analysis
def ha_sandbox(file):
    url = 'https://www.hybrid-analysis.com/api/v2/submit/file'
    files = {'file': open(file, "rb")}

    params = {'environment_id': 120, 'no_share_third_party': 1, 'allow_community_access': 1}

    HEADERS = {
        'User-Agent': 'Hybrid Analysis',
        'api-key': 'Your_HA_Key'
    }

    ha_req = requests.post(url, files=files, headers=HEADERS, data=params)

    if ha_req.status_code in [200, 201]:
        sha256 = ha_req.json()['sha256']
        environment_Id = ha_req.json()['environment_id']
        print('For Sandbox Results: https://www.hybrid-analysis.com/sample/{}?environmentId={} '.format(sha256,
                                                                                                    environment_Id))
        print('For Analysis Dashboard: https://www.hybrid-analysis.com/sample/{}'.format(sha256))

    else:
        print('Error with submission')
        print('Status Code: {}'.format(ha_req.status_code))
        print('Msg: {}'.format(ha_req.text))

def main():
    parser = PromptParser()
    parser.add_argument('--pcap', '-p', help='PCAP file to analyze', default='foo')
    pcap_file = parser.parse_args().pcap

    run_bro(pcap_file)
    for file in get_files('extract_files'):
        scan_file(file)
        ha_sandbox(file)


if __name__ == "__main__":
    main()


