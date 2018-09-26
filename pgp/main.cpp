#include<fstream>
#include<stdio.h>
#include<cstring>
#include<stdlib.h>
#include<openssl/aes.h>
#include<openssl/md5.h>
#include <windows.h>
#include<commdlg.h>
#include<tchar.h>
#include<openssl/bio.h>
#include<openssl/evp.h>
#include<openssl/ec.h>
#include<openssl/pem.h>
#include<iostream>

TCHAR constpath[MAX_PATH] = { 0 };
void constsave(char * buf,int length)
{
	std::fstream fout;
	fout.open(constpath, std::ios::binary | std::ios::out);
	fout.write(buf, length);
	fout.close();
}
void getopenpath(TCHAR * path)
{
	OPENFILENAME filepath;
	ZeroMemory(&filepath, sizeof(filepath));
	filepath.lpstrInitialDir = _T(".\\");//Ĭ�ϵ��ļ�·�� 
	filepath.hwndOwner = NULL;
	filepath.lStructSize = sizeof(filepath);
	filepath.lpstrFile = path;//����ļ��Ļ����� 
	filepath.nMaxFile = MAX_PATH;
	filepath.nFilterIndex = 0;
	filepath.Flags = OFN_PATHMUSTEXIST | OFN_EXPLORER;//��־����Ƕ�ѡҪ����OFN_ALLOWMULTISELECT
	GetOpenFileName(&filepath);
}

int eckeygenerate(char * pub,char * priv)
{
	EC_KEY * eckey = EC_KEY_new();
	int crvlen;
	EC_GROUP* group;
	unsigned int nid;
	crvlen = EC_get_builtin_curves(NULL, 0);
	EC_builtin_curve * curves = (EC_builtin_curve*)malloc(sizeof(EC_builtin_curve) * crvlen);
	EC_get_builtin_curves(curves, crvlen);
	srand((unsigned)time(NULL));
	nid = curves[rand() % crvlen].nid;
	group = EC_GROUP_new_by_curve_name(nid);
	EC_KEY_set_group(eckey, group);
	EC_KEY_generate_key(eckey);
	BIO* f1, *f2;
	f1 = BIO_new_file(pub, "wb");
	f2 = BIO_new_file(priv, "wb");
	int i = PEM_write_bio_EC_PUBKEY(f1, eckey);
	int j = PEM_write_bio_ECPrivateKey(f2, eckey, NULL, NULL, 0, NULL, NULL);
	BIO_flush(f1);
	BIO_flush(f2);
	BIO_free(f1);
	BIO_free(f2);
	EC_KEY_free(eckey);
	free(curves);
	return i * j;
}










int main()
{
	printf("1:����eckey 2:����pubkey 3:����privatekey 4:���ļ� 5:���� 6:���� 0:�˳�\n");
	int c;
	EC_KEY * eckey = NULL;
	int file_length_byte = 0;
	char * buf = NULL;
	int mod = 0;
	unsigned char *encrypt = NULL;
	unsigned char *plain = NULL;
	unsigned char *decrypt = NULL;
	long group_num = 0;
	while (1)
	{
		scanf("%d", &c);
		if (c == 1)
		{
			TCHAR privatepath[MAX_PATH] = { 0 };
			TCHAR publicpath[MAX_PATH] = { 0 };
			OPENFILENAME filepath = { 0 };
			ZeroMemory(&filepath, sizeof(filepath));
			filepath.lpstrInitialDir = _T(".\\");
			filepath.hwndOwner = NULL;
			filepath.lStructSize = sizeof(filepath);
			filepath.lpstrFile = privatepath;//����ļ��Ļ����� 
			filepath.nMaxFile = sizeof(privatepath) / sizeof(*privatepath);
			filepath.nFilterIndex = 0;
			filepath.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER;
			GetSaveFileName(&filepath);
			lstrcat(publicpath, privatepath);
			lstrcat(publicpath, _T("_pub"));
			int suc = eckeygenerate(publicpath, privatepath);
			if (suc) MessageBox(NULL, _T("�����ļ��ɹ�"), _T(" "), MB_OK);
			else
			{
				MessageBox(NULL, _T("�����ļ�ʧ��"), _T(" "), MB_OK);
				continue;
			}
			continue;
		}
		if (c == 2)
		{
			TCHAR pubpath[MAX_PATH] = { 0 };
			getopenpath(pubpath);
			BIO * f1;
			f1 = BIO_new_file(pubpath, "rb");
			eckey = PEM_read_bio_EC_PUBKEY(f1, NULL, NULL, NULL);
			BIO_flush(f1);
			BIO_free(f1);
			mod = 1;
			continue;
		}
		if (c == 3)
		{
			TCHAR pripath[MAX_PATH] = { 0 };
			getopenpath(pripath);
			BIO * f1 = BIO_new_file(pripath, "rb");
			eckey = PEM_read_bio_ECPrivateKey(f1, NULL, NULL, NULL);
			BIO_flush(f1);
			BIO_free(f1);
			mod = 0;
			continue;
		}
		if (c == 4)
		{
			getopenpath(constpath);
			if (mod == 0 && eckey)
			{
				unsigned int siglength = 0;
				std::fstream fin;
				fin.open(constpath, std::ios::binary | std::ios::in);
				fin.seekg(0, std::ios::end);
				long length = fin.tellg();
				fin.seekg(0);
				group_num = length / 8 + 3;
				buf = new char[group_num * 8];
				memset(buf, 0, group_num * 8 * sizeof(char));
				long * len0 = (long *)buf;
				len0[0] = length;
				fin.read(buf + 8, length);
				fin.close();
				unsigned char md[17] = { 0 };
				unsigned char * si = new unsigned char[ECDSA_size(eckey)+1];
				memset(si, 0, ECDSA_size(eckey) + 1);
				MD5((unsigned char *)buf, (group_num - 1) * 8, md);
				ECDSA_sign(0, md, 8, si, &siglength, eckey);
				len0[1] = siglength;
				int sign = ECDSA_verify(0, md, 8, si, siglength, eckey);



				strcat(buf + (group_num - 1) * 8, (char*)si);
				free(si);
				AES_KEY key;
				unsigned char userkey[AES_BLOCK_SIZE] = "114514";
				long length_byte = group_num * 8 * sizeof(char);
				encrypt = (unsigned char *)malloc(length_byte);
				memset((void*)encrypt, 0, length_byte);
				/*���ü���key����Կ����*/
				AES_set_encrypt_key(userkey, AES_BLOCK_SIZE * 8, &key);
				int len = 0;
				/*ѭ�����ܣ�ÿ��ֻ�ܼ���AES_BLOCK_SIZE���ȵ�����*/
				while (len < length_byte) {
					AES_encrypt((unsigned char *)buf + len, encrypt + len, &key);
					len += AES_BLOCK_SIZE;
				}
			}
			else
			{
				std::fstream fin;
				fin.open(constpath, std::ios::binary | std::ios::in);
				fin.seekg(0, std::ios::end);
				long length = fin.tellg();
				fin.seekg(0);
				file_length_byte = length *sizeof(char);
				buf = new char[length];
				fin.read(buf, length);
			};
			continue;
		}
		if (c == 5)
		{
			AES_KEY key;
			unsigned char userkey[AES_BLOCK_SIZE] = "114514";
			int len = 0;
			AES_set_decrypt_key(userkey, AES_BLOCK_SIZE * 8, &key);
			plain = (unsigned char *)malloc(file_length_byte);
			memset((void*)plain, 0, file_length_byte);
			/*ѭ������*/
			while (len < file_length_byte) {
				AES_decrypt((unsigned char *)buf + len, plain + len, &key);
				len += AES_BLOCK_SIZE;
			}
			unsigned char md[17];
			md[16] = 0;
			long * len1 = (long *)plain;
			int eclen = len1[1];
			len1[1] = 0;
			MD5((unsigned char *)plain, len1[0]+16, md);
			decrypt = new unsigned char[len1[0]+1];
			decrypt[len1[0]] = 0;
			memcpy(decrypt, plain + 8, len1[0]);
			unsigned char * test = plain + len1[0] + 8;
			int sign = ECDSA_verify(0, md, 8, test, eclen,eckey);


			
			
			continue;
		}
		if (c == 6)
		{
			if (encrypt != NULL)
			{
				if (constpath == NULL) continue;
				_tcscat(constpath, _T(".enc"));
				constsave((char *)encrypt, group_num * 8);
			}
			if (decrypt != NULL)
			{
				if (constpath == NULL) continue;
				_tcscat(constpath, _T(".dec"));
				constsave((char *)decrypt,file_length_byte/2);
			}
			continue;
		}
		if (c == 0)
		{
			break;
		}
	}
	return 0;

}