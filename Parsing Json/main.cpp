//
//  main.cpp
//  Parsing Json
//
//  Created by Prakhar Jain on 04/05/16.
//  Copyright © 2016 Prakhar Jain. All rights reserved.
//

#include <iostream>
#include <fstream>
#include <string>
#include <tuple>
#include <map>
#include <vector>
#include "cJSON.h"

using namespace std;

typedef tuple<string, string, string, string, string, int, string> ciphersuite;
map <int, int> map_count;
map <int, ciphersuite> map_detail;

map <string, int> map_ca;
void initialize_ciphersuite() {
    ifstream input("/Users/prakharjain/Documents/Xcode/Parsing Json/Parsing Json/ciphersuites.txt");
    string line;
    while (getline(input, line)) {
        int id;
        string suite_name;
        string version;
        string kx;
        string au;
        string enc;
        int keysize;
        string hash;
        input >> hex >> id >> suite_name >> version >> kx >> au >> enc >> dec >> keysize >> hash;
        ciphersuite temp(suite_name,version,kx,au,enc,keysize,hash);
        map_count[id] = 0;
        map_detail[id] = temp;
    }
    input.close();
}

void print_map_detail() {
    map<int, ciphersuite>::iterator it;
    
    for (it=map_detail.begin(); it!=map_detail.end(); ++it) {
        string suite_name;
        string version;
        string kx;
        string au;
        string enc;
        int keysize;
        string hash;
        tie (suite_name, version, kx, au, enc, keysize, hash) = it->second;
        cout << it->first << ": " << suite_name << " " << version << " " << kx << " " << au << " " <<  enc << " " <<  keysize << " " << hash << endl;
    }
}

void print_map_count() {
    map<int, int>::iterator it;
    for (it=map_count.begin(); it != map_count.end(); ++it) {
        cout << it->first << ": " << it->second << endl;
    }
}

int main(int argc, const char * argv[]) {
    //intialize all ciphersuites with 0
    initialize_ciphersuite();
    
    string filename = "/Users/prakharjain/Documents/Xcode/Parsing Json/Parsing Json/bank jsons/";
    
    int count_SSLv2 = 0;
    int count_SSLv3 = 0;
    int count_TLSv1_0 = 0;
    int count_TLSv1_1 = 0;
    int count_TLSv1_2 = 0;
    int count_client[4] = {0};
    int count_server[4] = {0};
    int count_complex[4] = {0};
    map <string, int> kx[5];
    map <string, int> au[5];
    map <string, int> enc[5];
    map <string, int> hash[5];
    map <string, int> cert;
    int cert_count[5] = {0};
    map <int, int> certlen;
    int count_validcert = 0;
    int count_invalidcert = 0;
    map <string, int> rootca;
    map <string, int> signhash;
    int count_secureRenegotiation = 0;
    int count_dhless2048 = 0;
    int count_ecdhless192 = 0;
    
    vector<string> servernames;
    for (int i = 0; i < 499; i++) {
        ifstream in(filename+to_string(i)+".json");
        string line;
        string data = "";
        while (getline(in, line))
            data += line + '\n';
        
        cJSON *json;
        json = cJSON_Parse(data.c_str());
        
        if (json) {
            string sni;
            sni = cJSON_GetObjectItem(json, "SNI")->valuestring;
            // for SSL/TLS versions
            cJSON *SSLv2, *SSLv3, *TLSv1_0, *TLSv1_1, *TLSv1_2;
            SSLv2 = cJSON_GetObjectItem(json, "SSLv2");
            SSLv3 = cJSON_GetObjectItem(json, "SSLv3");
            TLSv1_0 = cJSON_GetObjectItem(json, "TLSv1.0");
            TLSv1_1 = cJSON_GetObjectItem(json, "TLSv1.1");
            TLSv1_2 = cJSON_GetObjectItem(json, "TLSv1.2");
            map<string, bool> map_this_server_kx[5];
            map<string, bool> map_this_server_au[5];
            map<string, bool> map_this_server_enc[5];
            map<string, bool> map_this_server_hash[5];
            if (SSLv2) {
                count_SSLv2++;
                cJSON *suites = cJSON_GetObjectItem(SSLv2, "suites");
                int i;
                for (i = 0 ; i < cJSON_GetArraySize(suites) ; i++)
                {
                    cJSON * subitem = cJSON_GetArrayItem(suites, i);
                    int id = cJSON_GetObjectItem(subitem, "id")->valueint;
                    ciphersuite atuple = map_detail[id];
                    
                    if (map_this_server_kx[0][get<2>(atuple)] == false)
                        kx[0][get<2>(atuple)]++;
                    
                    if (map_this_server_au[0][get<3>(atuple)] == false)
                        au[0][get<3>(atuple)]++;
                    
                    map_this_server_kx[0][get<2>(atuple)] = true;
                    map_this_server_au[0][get<3>(atuple)] = true;
                    
                    if (map_this_server_enc[0][get<4>(atuple)] == false)
                        enc[0][get<4>(atuple)]++;
                    map_this_server_enc[0][get<4>(atuple)] = true;
                    
                    if (map_this_server_hash[0][get<6>(atuple)] == false)
                        hash[0][get<6>(atuple)]++;
                    map_this_server_hash[0][get<6>(atuple)] = true;
                }
            }
            if (SSLv3) {
                count_SSLv3++;
                string pref = cJSON_GetObjectItem(SSLv3, "suiteSelection")->valuestring;
                if (pref == "client")
                    count_client[0]++;
                else if (pref == "server")
                    count_server[0]++;
                else if (pref == "complex")
                    count_complex[0]++;
                cJSON *suites = cJSON_GetObjectItem(SSLv3, "suites");
                int i;
                for (i = 0 ; i < cJSON_GetArraySize(suites) ; i++)
                {
                    cJSON * subitem = cJSON_GetArrayItem(suites, i);
                    int id = cJSON_GetObjectItem(subitem, "id")->valueint;
                    ciphersuite atuple = map_detail[id];
                    if (map_this_server_kx[1][get<2>(atuple)] == false)
                        kx[1][get<2>(atuple)]++;
                    
                    if (map_this_server_au[1][get<3>(atuple)] == false)
                        au[1][get<3>(atuple)]++;
                    
                    map_this_server_kx[1][get<2>(atuple)] = true;
                    map_this_server_au[1][get<3>(atuple)] = true;
                    
                    if (map_this_server_enc[1][get<4>(atuple)] == false)
                        enc[1][get<4>(atuple)]++;
                    map_this_server_enc[1][get<4>(atuple)] = true;
                    
                    if (map_this_server_hash[1][get<6>(atuple)] == false)
                        hash[1][get<6>(atuple)]++;
                    map_this_server_hash[1][get<6>(atuple)] = true;
                }
            }
            if (TLSv1_0) {
                count_TLSv1_0++;
                string pref = cJSON_GetObjectItem(TLSv1_0, "suiteSelection")->valuestring;
                if (pref == "client")
                    count_client[1]++;
                else if (pref == "server")
                    count_server[1]++;
                else if (pref == "complex")
                    count_complex[1]++;
                cJSON *suites = cJSON_GetObjectItem(TLSv1_0, "suites");
                int i;
                for (i = 0 ; i < cJSON_GetArraySize(suites) ; i++)
                {
                    cJSON * subitem = cJSON_GetArrayItem(suites, i);
                    int id = cJSON_GetObjectItem(subitem, "id")->valueint;
                    ciphersuite atuple = map_detail[id];
                    if (map_this_server_kx[2][get<2>(atuple)] == false)
                        kx[2][get<2>(atuple)]++;
                    
                    if (map_this_server_au[2][get<3>(atuple)] == false)
                        au[2][get<3>(atuple)]++;
                    
                    map_this_server_kx[2][get<2>(atuple)] = true;
                    map_this_server_au[2][get<3>(atuple)] = true;
                    
                    if (map_this_server_enc[2][get<4>(atuple)] == false)
                        enc[2][get<4>(atuple)]++;
                    map_this_server_enc[2][get<4>(atuple)] = true;
                    
                    if (map_this_server_hash[2][get<6>(atuple)] == false)
                        hash[2][get<6>(atuple)]++;
                    map_this_server_hash[2][get<6>(atuple)] = true;
                }
            }
            if (TLSv1_1) {
                count_TLSv1_1++;
                string pref = cJSON_GetObjectItem(TLSv1_1, "suiteSelection")->valuestring;
                if (pref == "client")
                    count_client[2]++;
                else if (pref == "server")
                    count_server[2]++;
                else if (pref == "complex")
                    count_complex[2]++;
                cJSON *suites = cJSON_GetObjectItem(TLSv1_1, "suites");
                int i;
                for (i = 0 ; i < cJSON_GetArraySize(suites) ; i++)
                {
                    cJSON * subitem = cJSON_GetArrayItem(suites, i);
                    int id = cJSON_GetObjectItem(subitem, "id")->valueint;
                    ciphersuite atuple = map_detail[id];
                    if (map_this_server_kx[3][get<2>(atuple)] == false)
                        kx[3][get<2>(atuple)]++;
                    
                    if (map_this_server_au[3][get<3>(atuple)] == false)
                        au[3][get<3>(atuple)]++;
                    
                    map_this_server_kx[3][get<2>(atuple)] = true;
                    map_this_server_au[3][get<3>(atuple)] = true;
                    
                    if (map_this_server_enc[3][get<4>(atuple)] == false)
                        enc[3][get<4>(atuple)]++;
                    map_this_server_enc[3][get<4>(atuple)] = true;
                    
                    if (map_this_server_hash[3][get<6>(atuple)] == false)
                        hash[3][get<6>(atuple)]++;
                    map_this_server_hash[3][get<6>(atuple)] = true;
                }
            }
            if (TLSv1_2) {
                count_TLSv1_2++;
                string pref = cJSON_GetObjectItem(TLSv1_2, "suiteSelection")->valuestring;
                if (pref == "client")
                    count_client[3]++;
                else if (pref == "server")
                    count_server[3]++;
                else if (pref == "complex")
                    count_complex[3]++;
                cJSON *suites = cJSON_GetObjectItem(TLSv1_2, "suites");
                int i;
                for (i = 0 ; i < cJSON_GetArraySize(suites) ; i++)
                {
                    cJSON * subitem = cJSON_GetArrayItem(suites, i);
                    int id = cJSON_GetObjectItem(subitem, "id")->valueint;
                    ciphersuite atuple = map_detail[id];
                    if (map_this_server_kx[4][get<2>(atuple)] == false)
                        kx[4][get<2>(atuple)]++;
                    
                    if (map_this_server_au[4][get<3>(atuple)] == false)
                        au[4][get<3>(atuple)]++;
                    
                    map_this_server_kx[4][get<2>(atuple)] = true;
                    map_this_server_au[4][get<3>(atuple)] = true;
                    
                    if (map_this_server_enc[4][get<4>(atuple)] == false)
                        enc[4][get<4>(atuple)]++;
                    map_this_server_enc[4][get<4>(atuple)] = true;
                    
                    if (map_this_server_hash[4][get<6>(atuple)] == false)
                        hash[4][get<6>(atuple)]++;
                    map_this_server_hash[4][get<6>(atuple)] = true;
                }
            }
            
            cJSON *ssl3chains = cJSON_GetObjectItem(json, "ssl3Chains");
            int validcert[5] = {-1,-1,-1,-1,-1};
            int count_cert = 0;
            for (int j = 0 ; j < cJSON_GetArraySize(ssl3chains) ; j++)
            {
                count_cert++;
                cJSON * subitem = cJSON_GetArrayItem(ssl3chains, j);
                int length = cJSON_GetObjectItem(subitem, "length")->valueint;
                certlen[length]++;
                validcert[j] = cJSON_GetObjectItem(subitem, "decoded")->valueint;
                cJSON *certificates = cJSON_GetObjectItem(subitem, "certificates");
                cJSON *subsubitem = cJSON_GetObjectItem(certificates, 0);
                string name = cJSON_GetObjectItem(subsubitem, "KeyType")->valuestring;
                int keysize = cJSON_GetObjectItem(subsubitem, "KeySize")->valueint;
                cert[name+to_string(keysize)]++;
                string root;
                for (int k = 0; k < cJSON_GetArraySize(certificates); k++) {
                    cJSON *subsubitem = cJSON_GetArrayItem(certificates, k);
                    root = cJSON_GetObjectItem(subsubitem, "issuer")->valuestring;
                }
                rootca[root]++;
                cJSON *signHashes = cJSON_GetObjectItem(subitem, "signHashes");
                for (int k = 0; k < cJSON_GetArraySize(signHashes); k++) {
                    signhash[cJSON_GetArrayItem(signHashes, k)->valuestring]++;
                }
            }
            cert_count[count_cert]++;
            for (int j = 0; j < 5; j++) {
                if (validcert[j] == true)
                    count_validcert++;
                else if (validcert[j] != -1)
                    count_invalidcert++;
            }
            
            if (cJSON_GetObjectItem(json, "secureRenegotiation")->valueint == true)
                count_secureRenegotiation++;
            cJSON *warnings = cJSON_GetObjectItem(json, "warnings");
            for (int j = 0; j < cJSON_GetArraySize(warnings); j++) {
                cJSON *subitem = cJSON_GetArrayItem(warnings, j);
                string id = cJSON_GetObjectItem(subitem, "id")->valuestring;
                if (id == "SK002")
                    count_dhless2048++;
                if (id == "SK003")
                    count_ecdhless192++;
            }
        }
    }
    cout << "Total Number of Servers with\nSSLv2: " << count_SSLv2 << "\nSSLv3: " << count_SSLv3 << "\nTLSv1.0: " << count_TLSv1_0 << "\nTLSv1.1: " << count_TLSv1_1 << "\nTLSv1.2: " << count_TLSv1_2 << endl;
    cout << "Preference Client Server Complex" << endl;
    cout << "SSLv3 : " << count_client[0] << " " << count_server[0] << " " << count_complex[0] << endl;
    cout << "TLSv1.0 : " << count_client[1] << " " << count_server[1] << " " << count_complex[1] << endl;
    cout << "TLSv1.1 : " << count_client[2] << " " << count_server[2] << " " << count_complex[2] << endl;
    cout << "TLSv1.2 : " << count_client[3] << " " << count_server[3] << " " << count_complex[3] << endl;
    map<string, int>::iterator it;
    cout << "SSLv2\n";
    cout << "Key Exchange\n";
    for (it = kx[0].begin(); it != kx[0].end(); it++) {
        cout << it->first << " : "  << it->second << endl;
    }
    cout << "Authentication\n";
    for (it = au[0].begin(); it != au[0].end(); it++) {
        cout << it->first << " : " << it->second << endl;
    }
    cout << "SSLv3\n";
    cout << "Key Exchange\n";
    for (it = kx[1].begin(); it != kx[1].end(); it++) {
        cout << it->first << " : "  << it->second << endl;
    }
    cout << "Authentication\n";
    for (it = au[1].begin(); it != au[1].end(); it++) {
        cout << it->first << " : " << it->second << endl;
    }
    cout << "TLSv1.0\n";
    cout << "Key Exchange\n";
    for (it = kx[2].begin(); it != kx[2].end(); it++) {
        cout << it->first << " : "  << it->second << endl;
    }
    cout << "Authentication\n";
    for (it = au[2].begin(); it != au[2].end(); it++) {
        cout << it->first << " : " << it->second << endl;
    }
    cout << "TLSv1.1\n";
    cout << "Key Exchange\n";
    for (it = kx[3].begin(); it != kx[3].end(); it++) {
        cout << it->first << " : "  << it->second << endl;
    }
    cout << "Authentication\n";
    for (it = au[3].begin(); it != au[3].end(); it++) {
        cout << it->first << " : " << it->second << endl;
    }
    cout << "TLSv1.2\n";
    cout << "Key Exchange\n";
    for (it = kx[4].begin(); it != kx[4].end(); it++) {
        cout << it->first << " : "  << it->second << endl;
    }
    cout << "Authentication\n";
    for (it = au[4].begin(); it != au[4].end(); it++) {
        cout << it->first << " : " << it->second << endl;
    }
    cout << "Encryption Algorithm\n";
    cout << "SSLv2\n";
    for (it = enc[0].begin(); it != enc[0].end(); it++) {
        cout << it->first << " : " << it->second << endl;
    }
    cout << "SSLv3\n";
    for (it = enc[1].begin(); it != enc[1].end(); it++) {
        cout << it->first << " : " << it->second << endl;
    }
    cout << "TLSv1.0\n";
    for (it = enc[2].begin(); it != enc[2].end(); it++) {
        cout << it->first << " : " << it->second << endl;
    }
    cout << "TLSv1.1\n";
    for (it = enc[3].begin(); it != enc[3].end(); it++) {
        cout << it->first << " : " << it->second << endl;
    }
    cout << "TLSv1.2\n";
    for (it = enc[4].begin(); it != enc[4].end(); it++) {
        cout << it->first << " : " << it->second << endl;
    }
    
    cout << "Hashing algorithm for PRF/MAC\n";
    cout << "SSLv2\n";
    for (it = hash[0].begin(); it != hash[0].end(); it++) {
        cout << it->first << " : " << it->second << endl;
    }
    cout << "SSLv3\n";
    for (it = hash[1].begin(); it != hash[1].end(); it++) {
        cout << it->first << " : " << it->second << endl;
    }
    cout << "TLSv1.0\n";
    for (it = hash[2].begin(); it != hash[2].end(); it++) {
        cout << it->first << " : " << it->second << endl;
    }
    cout << "TLSv1.1\n";
    for (it = hash[3].begin(); it != hash[3].end(); it++) {
        cout << it->first << " : " << it->second << endl;
    }
    cout << "TLSv1.2\n";
    for (it = hash[4].begin(); it != hash[4].end(); it++) {
        cout << it->first << " : " << it->second << endl;
    }
    
    cout << "Number of certificates possessed by server\n";
    for (int i = 0; i < 5; i++) {
        cout << i << " : " << cert_count[i] << endl;
    }
    
    cout << "Certificate Types\n";
    for (it = cert.begin(); it != cert.end(); it++) {
        cout << it->first << " : " << it->second << endl;
    }
    
    cout << "Certificate Chain Length\n";
    map <int, int> :: iterator iter;
    for (iter = certlen.begin(); iter != certlen.end(); iter++) {
        cout << iter->first << " : " << iter->second << endl;
    }
    cout << "Certificate Validity\n";
    cout << "Valid : " << count_validcert << endl;
    cout << "Invalid : " << count_invalidcert << endl;
    
    cout << "Root CAs\n";
    for (it = rootca.begin(); it != rootca.end(); it++) {
        cout << it->first << " : " << it->second << endl;
    }
    
    cout << "Sign Hashes\n";
    for (it = signhash.begin(); it != signhash.end(); it++) {
        cout << it->first << " : " << it->second << endl;
    }

    cout << "Secure Renegotiation by " << count_secureRenegotiation << " servers" << endl;
    
    cout << "DH smaller than 2048 by " << count_dhless2048 << "servers" << endl;
    cout << "ECDH smaller than 192 by " << count_ecdhless192 << "servers" << endl;
    return 0;
}
