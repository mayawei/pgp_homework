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
	f1 = BIO_new_file(pub, "w");
	f2 = BIO_new_file(priv, "w");
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

void pubkeyimport(char * pub, EC_KEY * eckey)
{
	BIO * f1;
	f1 = BIO_new_file(pub, "r");
	eckey = PEM_read_bio_EC_PUBKEY(f1, NULL, NULL, NULL);
	BIO_flush(f1);
	BIO_free(f1);
};
void prikeyimport(char * pri, EC_KEY * eckey)
{
	BIO * f1;
	f1 = BIO_new_file(pri, "r");
	eckey = PEM_read_bio_ECPrivateKey(f1, NULL, NULL, NULL);
	BIO_flush(f1);
	BIO_free(f1);
};










int main()
{
	printf("1:生成eckey 2:导入pubkey 3:导入privatekey 4:打开文件 5:解密 6:保存 0:退出\n");
	int c;
	EC_KEY * pubkey = NULL;
	EC_KEY * prikey = NULL;
	int file_length = 0;
	char * buf = NULL;
	while (1)
	{
		scanf("%d", &c);
		if (c == 1)
		{
			TCHAR privatepath[MAX_PATH] = { 0 };
			TCHAR publicpath[MAX_PATH] = { 0 };
			OPENFILENAME filepath = { 0 };
			filepath.lpstrInitialDir = _T(".\\");//默认的文件路径 
			//filepath.lpstrFilter = _T("(*.*)\0");//要选择的文件后缀 
			filepath.hwndOwner = NULL;
			filepath.lStructSize = sizeof(filepath);
			filepath.lpstrFile = privatepath;//存放文件的缓冲区 
			filepath.nMaxFile = sizeof(privatepath) / sizeof(*privatepath);
			filepath.nFilterIndex = 0;
			filepath.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER;//标志如果是多选要加上OFN_ALLOWMULTISELECT
			GetSaveFileName(&filepath);
			lstrcat(publicpath,privatepath);
			lstrcat(publicpath, _T("_pub"));
			int suc = eckeygenerate(publicpath, privatepath);
			if (suc) MessageBox(NULL, _T("保存文件成功"), _T(" "), MB_OK);
			else
			{
				MessageBox(NULL, _T("保存文件失败"), _T(" "), MB_OK);
				continue;
			}
			continue;
		}
		if (c == 2)
		{
			TCHAR pubpath[MAX_PATH] = { 0 };
			OPENFILENAME filepath = { 0 };
			filepath.lpstrInitialDir = _T(".\\");//默认的文件路径 
			filepath.hwndOwner = NULL;
			filepath.lpstrTitle = _T("pubkey");
			filepath.lStructSize = sizeof(filepath);
			filepath.lpstrFile = pubpath;//存放文件的缓冲区 
			filepath.nMaxFile = sizeof(pubpath) / sizeof(*pubpath);
			filepath.nFilterIndex = 0;
			filepath.Flags = OFN_PATHMUSTEXIST | OFN_EXPLORER;//标志如果是多选要加上OFN_ALLOWMULTISELECT
			GetSaveFileName(&filepath);
			pubkeyimport(pubpath, pubkey);
			continue;
		}
		if (c == 3)
		{
			TCHAR pripath[MAX_PATH] = { 0 };
			OPENFILENAME filepath = { 0 };
			filepath.lpstrInitialDir = _T(".\\");//默认的文件路径 
			filepath.hwndOwner = NULL;
			filepath.lpstrTitle = _T("prikey");
			filepath.lStructSize = sizeof(filepath);
			filepath.lpstrFile = pripath;//存放文件的缓冲区 
			filepath.nMaxFile = sizeof(pripath) / sizeof(*pripath);
			filepath.nFilterIndex = 0;
			filepath.Flags = OFN_PATHMUSTEXIST | OFN_EXPLORER;//标志如果是多选要加上OFN_ALLOWMULTISELECT
			GetSaveFileName(&filepath);
			pubkeyimport(pripath, prikey);
			continue;
		}

		if (c == 4)
		{
			TCHAR filename[MAX_PATH] = { 0 };
			OPENFILENAME filepath = { 0 };
			filepath.lpstrInitialDir = _T(".\\");//默认的文件路径 
			filepath.hwndOwner = NULL;
			filepath.lStructSize = sizeof(filepath);
			filepath.lpstrFile = filename;//存放文件的缓冲区 
			filepath.nMaxFile = sizeof(filename) / sizeof(*filename);
			filepath.nFilterIndex = 0;
			filepath.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER;//标志如果是多选要加上OFN_ALLOWMULTISELECT
		fai:	BOOL bSel = GetOpenFileName(&filepath);
			if (bSel) MessageBox(NULL, _T("打开文件成功"), _T(" "), MB_OK);
			else
			{



				MessageBox(NULL, _T("打开文件失败"), _T(" "), MB_OK);
				goto fai;
			}
			std::fstream fin;
			fin.open(filename, std::ios::binary|std::ios::in);
			fin.seekg(0, std::ios::end);
			long length = fin.tellg();
			fin.seekg(0);
			long group_num = length / 8 + 3;
			buf = (char *)malloc(group_num * 8 * sizeof(char));
			memset(buf, 0, group_num * 8 * sizeof(char));
			long * len = (long *)buf;
			len[0] = group_num;
			fin.read(buf+8, length);
			std::cout << buf +  8 << std::endl;
			unsigned char md[9] = {0};

			unsigned int l = 128;
			EVP_MD_CTX * md_ctx = EVP_MD_CTX_new();
			EVP_MD_CTX_init(md_ctx);
			EVP_DigestInit(md_ctx, EVP_md5());
			EVP_DigestUpdate(md_ctx, buf, group_num * 8 * 2);
			EVP_DigestFinal(md_ctx, md, &l);
			EVP_MD_CTX_free(md_ctx);





			//MD5((unsigned char *)buf, group_num * 8 * 2, md);
			strcat(buf + (group_num - 1) * 8, (char*)md);

			std::cout << buf + (group_num - 1) * 8 <<std::endl;
			std::cout << md;
			continue;
		}
		


		
		//AES_KEY key;
		//unsigned char userkey[AES_BLOCK_SIZE] = "114514";



		//unsigned char *encrypt = (unsigned char *)malloc(length_byte);
		//unsigned char *plain = (unsigned char *)malloc(length_byte);





		//memset((void*)encrypt, 0, length_byte);
		//memset((void*)plain, 0, length_byte);

		///*设置加密key及密钥长度*/
		//AES_set_encrypt_key(userkey, AES_BLOCK_SIZE * 8, &key);

		//int len = 0;
		///*循环加密，每次只能加密AES_BLOCK_SIZE长度的数据*/
		//while (len < length_byte) {
		//	AES_encrypt((unsigned char *)buf + len, encrypt + len, &key);
		//	len += AES_BLOCK_SIZE;
		//}
		///*设置解密key及密钥长度*/
		//AES_set_decrypt_key(userkey, AES_BLOCK_SIZE * 8, &key);

		//len = 0;
		///*循环解密*/
		//while (len < length_byte) {
		//	AES_decrypt(encrypt + len, plain + len, &key);
		//	len += AES_BLOCK_SIZE;
		//}

		getchar();
	}
	free(pubkey);
	free(prikey);
	return 0;

}