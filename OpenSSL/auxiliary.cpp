#include <Windows.h>
#include<iostream>
#include<map>

namespace ADAPTIVA_AUX {
	static char base32EncodingTable[] = "hmw5c98fqe6r3xt4yupadgjk7slnbv2z";
	static std::map<char, unsigned char>base32DecodeMap = { 
		{'h', 0}, {'m', 1}, {'w', 2}, {'5', 3}, {'c', 4}, {'9', 5}, {'8', 6}, {'f', 7}, 
		{'q', 8}, {'e', 9}, {'6', 10}, {'r', 11}, {'3', 12}, {'x', 13},	{'t', 14}, {'4', 15}, 
		{'y', 16}, {'u', 17}, {'p', 18}, {'a',19}, {'d', 20}, {'g', 21}, {'j', 22}, {'k', 23}, 
		{'7', 24}, {'s', 25}, {'l', 26}, {'n', 27}, {'b', 28}, {'v', 29}, {'2', 30}, {'z',31}
	};

	char* base32Encode(byte* p, size_t l)
	{
		size_t bits = l * 8;
		int r = bits % 5;
		size_t outLength = (r > 0) ? (bits / 5 + 1) : (bits / 5);

		outLength++;
		char* out = (char*)calloc(outLength, sizeof(unsigned char));

		size_t byteIndex = 0;
		int bitIndex = 0;
		size_t outIndex = 0;
		while (byteIndex <= l - 1 || bitIndex <= 8 - 1)
		{

			//  0  1  2  3  4  5  6  7
			//        |
			//       bit index
			if (7 - bitIndex - 1 >= 5)
			{
				byte b = *(p + byteIndex);
				int unusedBitsOnTheRight = 7 - (bitIndex + 5 - 1);
				b = b >> unusedBitsOnTheRight;
				b = b & 0b00011111;
				out[outIndex] = base32EncodingTable[b];
				outIndex++;
				bitIndex = bitIndex + 5;
			}
			else
			{
				int bitsLeftInThisByte = 7 - bitIndex + 1;
				int unusedBitsOnTheLeft = 8 - bitsLeftInThisByte;
				byte mask = 0xff;
				mask = mask >> unusedBitsOnTheLeft;
				byte b = *(p + byteIndex);
				b = b & mask;
				if (byteIndex < l - 1)
				{
					byteIndex++;
					int bitsNeedInNextByte = 5 - bitsLeftInThisByte;
					int unusedBitsOnTheRight = 8 - bitsNeedInNextByte;

					byte b2 = *(p + byteIndex);
					b2 = b2 >> unusedBitsOnTheRight;

					b = b << bitsNeedInNextByte;
					b = b | b2;
					out[outIndex] = base32EncodingTable[b];
					outIndex++;
					bitIndex = bitsNeedInNextByte;
				}
				else
				{
					// pad a few zeros

					int bitsNeedInNextByte = 5 - bitsLeftInThisByte;
					b = b << bitsNeedInNextByte;
					out[outIndex] = base32EncodingTable[b];
					break;
				}
			}
		}
		return out;
	}

	byte* base32Decode(char* pszIn, int* outSize)
	{
		size_t l = strlen(pszIn);
		size_t bits = (l - 1) * 5;

		size_t outLength;
		if ((bits + 1) % 8 == 0)
			outLength = (bits + 1) / 8;
		else if ((bits + 2) % 8 == 0)
			outLength = (bits + 2) / 8;
		else if ((bits + 3) % 8 == 0)
			outLength = (bits + 3) / 8;
		else if ((bits + 4) % 8 == 0)
			outLength = (bits + 4) / 8;
		else
			outLength = (bits + 5) / 8;

		byte* out = (byte*)calloc(outLength, sizeof(unsigned char));
		*outSize = outLength;
		size_t inIndex = 0;
		size_t byteIndex = 0;
		int bitIndex = 0;
		while (true)
		{
			byte a = base32DecodeMap[pszIn[inIndex]];

			if (7 - bitIndex - 1 >= 5)
			{
				byte b = out[byteIndex];
				int unusedBitsOnTheRight = 7 - (bitIndex + 5 - 1);
				b = b >> unusedBitsOnTheRight;
				b = b | a;
				b = b << unusedBitsOnTheRight;
				out[byteIndex] = b;
				bitIndex += 5;
				inIndex++;
			}
			else
			{
				int bitsLeftInThisByte = 7 - bitIndex + 1;
				int bitsToFillInNextByte = 5 - bitsLeftInThisByte;
				byte c = a >> bitsToFillInNextByte;
				byte b = out[byteIndex];
				b = b | c;
				out[byteIndex] = b;
				if (byteIndex == outLength - 1)
					break;
				else
				{
					byteIndex++;
					int unusedOnTheLeft = 8 - bitsToFillInNextByte;
					out[byteIndex] = a << unusedOnTheLeft;
					bitIndex = bitsToFillInNextByte;
					inIndex++;
				}
			}
		}
		return out;
	}
}