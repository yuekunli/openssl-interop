#include <iostream>
#include <sstream>

#include <openssl/objects.h>

using namespace std;

namespace OPENSSL_ASN1_TEST {

	/**
	* Given an OID in numeric-dot notation, find the long name
	* Steps:
	*  (1). construct a dummy object with the numeric-dot notation,
	*       OpenSSL internally serializes the OID into binary format and creates a dummy object with that OID
	*  (2). search registered objects, looking the the one that matches the serialized OID
	*/
	void openssl_asn1_test1()
	{
		string md5_dot_oid = "1.2.840.113549.2.5";

		// ASN1_OBJECT *OBJ_txt2obj(const char *s, int no_name);

		ASN1_OBJECT* md5_dummy_obj = OBJ_txt2obj(md5_dot_oid.c_str(), 1/*not a name, construct an object instead of searching*/);

		int nid = OBJ_obj2nid(md5_dummy_obj);

		const char* s = OBJ_nid2ln(nid);

		cout << s << "\n";

	}

	/*
	* Convert binary OID to numeric-dot notation
	*/
	string openssl_asn1_test_oid_bin2dot(unsigned char* p, size_t length)
	{
		stringstream ss1;

		for (size_t i = 0; i < length; i++)
		{
			if (i == 0)
			{
				unsigned char a = p[0];
				unsigned char a1 = a / 40;
				unsigned char a2 = a % 40;
				ss1 << (unsigned short)a1 << '.' << (unsigned short)a2 << '.';
			}
			else
			{
				unsigned char a = p[i];
				if ((a & 0x80) == 0)
				{
					ss1 << (unsigned short)a << '.';
				}
				else
				{
					unsigned long b = 0;
					a = a & 0x7f; // clear the highest bit in 'a'
					unsigned long c = (unsigned long)a; // c and b have the same length, the lowest 7 bits of c are meaningful
					b = b | c;
					i++;
					a = p[i];
					while ((a & 0x80) != 0)
					{
						a = a & 0x7f;
						c = (unsigned long)a;
						b = b << 7;
						b = b | c;
						i++;
						a = p[i];
					}
					c = (unsigned long)a;
					b = b << 7;
					b = b | c;
					ss1 << b << '.';
				}
			}
		}

		string s;
		ss1 >> s;
		size_t l = s.length();
		string final_string = s.substr(0, l-1);

		return final_string;
	}


	void openssl_asn1_test2()
	{
		unsigned char md5_oid_bin[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05 };

		string oid_dot = openssl_asn1_test_oid_bin2dot(md5_oid_bin, sizeof(md5_oid_bin));

		ASN1_OBJECT* md5_dummy_obj = OBJ_txt2obj(oid_dot.c_str(), 1/*not a name, construct an object instead of searching*/);

		int nid = OBJ_obj2nid(md5_dummy_obj);

		const char* s = OBJ_nid2ln(nid);

		cout << s << "\n";

	}
}