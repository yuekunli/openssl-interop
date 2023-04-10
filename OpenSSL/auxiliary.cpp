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

		outLength++; // output is an ASCII string that is terminated by '\0'
		char* out = (char*)calloc(outLength, sizeof(unsigned char)); // using calloc so that the last byte is '\0'

		size_t byteIndex = 0;
		int bitIndex = 0;
		size_t outIndex = 0;
		while (byteIndex <= l - 1 || bitIndex <= 8 - 1) // probably just "byteIndex <= l - 1" is enough
		{

			//  0  1  2  3  4  5  6  7
			//        |
			//       bit index
			if (7 - bitIndex + 1 >= 5)
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


	/*
	* 
	* original    0  1  1  0  1  0  1  0  1  1  0  0  1  0  0  1
	*            |              |              |              |    0 0 0 0   (pad 4 zeros)
	* 
	* encoding output has 4 characters (not counting the terminating '\0')
	* each of the first 3 characters represents 5 bits in the original array
	* the last character may represent 1, 2, 3, 4, or 5 bits in the original array
	* 
	* The number of bits in the original array must be multiple of 8, because the origianl array is passed to
	* the encoding function as an array of bytes.
	* 
	* 
	*/

	byte* base32Decode(char* pszIn, int* outSize)
	{
		size_t l = strlen(pszIn);  // strlen doesn't include terminating '\0'
		size_t bits = (l - 1) * 5; // number of bits represented by the first a few characters (excluding the last character)

		size_t outLength;
		if ((bits + 1) % 8 == 0)  // if the last character represents 1 bit
			outLength = (bits + 1) / 8;
		else if ((bits + 2) % 8 == 0)  // if the last character represents 2 bits
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

			if (7 - bitIndex + 1 >= 5)
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




namespace ADAPTIVA_AUX2 {
	static char base32EncodingTable[] = "hmw5c98fqe6r3xt4yupadgjk7slnbv2z";
	static std::map<char, unsigned char>base32DecodeMap = {
		{'h', 0}, {'m', 1}, {'w', 2}, {'5', 3}, {'c', 4}, {'9', 5}, {'8', 6}, {'f', 7},
		{'q', 8}, {'e', 9}, {'6', 10}, {'r', 11}, {'3', 12}, {'x', 13},	{'t', 14}, {'4', 15},
		{'y', 16}, {'u', 17}, {'p', 18}, {'a',19}, {'d', 20}, {'g', 21}, {'j', 22}, {'k', 23},
		{'7', 24}, {'s', 25}, {'l', 26}, {'n', 27}, {'b', 28}, {'v', 29}, {'2', 30}, {'z',31}
	};


	unsigned char getLowerBitsInByteAndLeftShift(unsigned char b, int n, int shift)
	{
		return (b & (0xff >> (8 - n))) << shift;
	}


	unsigned char getHigherBitsInByteAndRightShiftToEnd(unsigned char b, int n)
	{
		return (b & (0xff << (8 - n))) >> (8 - n);
	}

	unsigned char getMiddleBitsInByteAndRightShiftToEnd(unsigned char b, int start, int n)
	{
		int remainOnTheRight = 7 - (start + n - 1);
		return (b >> remainOnTheRight) & (0xff >> (8-n));
	}

	/*
	* 
	* start: 158;
	* bitsCount = 6;
	* Given a byte array pointed at by p, give me the value of 6 consecutive bits, starting at 158th bit.
	* (bit's index starts at 0)
	* 
	* start: bit's index
	* bitsCount: number of bits
	*/
	unsigned char getValueOfBits(byte* p, size_t start, int bitsCount)
	{
		size_t byteIndex = start / 8;

		int bitIndex = start - byteIndex * 8;

		if (bitIndex + bitsCount - 1 <= 7)
		{
			return getMiddleBitsInByteAndRightShiftToEnd(p[byteIndex], bitIndex, 5);
		}
		else
		{
			int bitsInThisByte = 7 - bitIndex + 1;
			int bitsInNextByte = bitsCount - bitsInThisByte;

			unsigned char a = getLowerBitsInByteAndLeftShift(p[byteIndex], bitsInThisByte, bitsInNextByte);
			unsigned char b = getHigherBitsInByteAndRightShiftToEnd(p[byteIndex + 1], bitsInNextByte);

			return a | b;
		}
	}

	char* base32Encode(byte* p, size_t l)
	{
		size_t bits = l * 8;
		int r = bits % 5;
		size_t outLength = (r > 0) ? (bits / 5 + 1) : (bits / 5);

		outLength++; // output is an ASCII string that is terminated by '\0'
		char* out = (char*)calloc(outLength, sizeof(unsigned char)); // using calloc so that the last byte is '\0'

		int bitIndex = 0;
		size_t outIndex = 0;

		/*
		* example, if I have 3 bytes, there are 24 bits. 0th -- 23rd.
		* 20th, 21st, 22nd, 23rd   --- this group need padding.
		* bits - (bits / 5) * 5 = 4   ---  that last 4 bits need padding.
		* bits - 4 = 20  -- the index of the bit at the beginning of the group that needs padding
		* 
		* if number of bits is a multiple of 5, for example 40,
		* (bits / 5 ) * 5 = 40
		* The 40th bit is the beginning of the group that needs padding, we'll never reach to 40th bits
		*/

		size_t indexOfGroupNeedPadding = (bits / 5 ) * 5;

		while (bitIndex < indexOfGroupNeedPadding)
		{
			unsigned char a = getValueOfBits(p, bitIndex, 5);
			out[outIndex] = base32EncodingTable[a];
			bitIndex += 5;
			outIndex++;
		}
		if (bitIndex < bits)
		{
			unsigned char a = getLowerBitsInByteAndLeftShift(p[l - 1], bits - bitIndex, 5 - (bits - bitIndex));
			out[outIndex] = base32EncodingTable[a];
		}

		return out;
	}



	void setLowerBitsWithTheHighBitsOfAnotherByte(byte* b, int n, byte v, int usedBitsInV)
	{
		unsigned char a = getMiddleBitsInByteAndRightShiftToEnd(v, 8 - usedBitsInV, n);
		*b = (*b) | a;
	}

	void setHigherBitsWithTheLowBitsOfAnotherByte(byte* b, int n, byte v)
	{
		unsigned char a = getLowerBitsInByteAndLeftShift(v, n, (8 - n));
		*b = (*b) | a;
	}

	void setMiddleBits(byte* b, int start, int n, unsigned char v)
	{
		int remainOnTheRight = 7 - (start + n - 1);
		*b = (*b) | (v << remainOnTheRight);
	}

	void setBitsValue(byte* p, int start, int n, unsigned char v)
	{
		size_t byteIndex = start / 8;

		int bitIndex = start - byteIndex * 8;

		if (bitIndex + n - 1 <= 7)
		{
			return setMiddleBits(p+byteIndex, bitIndex, 5, v);
		}
		else
		{
			int bitsInThisByte = 7 - bitIndex + 1;
			int bitsInNextByte = n - bitsInThisByte;

			setLowerBitsWithTheHighBitsOfAnotherByte(p+byteIndex, bitsInThisByte, v, 5);
			setHigherBitsWithTheLowBitsOfAnotherByte(p+byteIndex + 1, bitsInNextByte, v);
		}
	}

	byte* base32Decode(char* pszIn, int* outSize)
	{
		size_t l = strlen(pszIn);
		size_t bits = (l - 1) * 5;
		int padding;
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

		padding = l * 5 - outLength * 8;
		byte* out = (byte*)calloc(outLength, sizeof(unsigned char));
		*outSize = outLength;

		size_t inIndex = 0;
		size_t byteIndex = 0;
		int bitIndex = 0;

		// pszIn :   a  x  t  \0
		// l = 3
		while (inIndex < l-1)
		{
			byte v = base32DecodeMap[pszIn[inIndex]];

			setBitsValue(out, bitIndex, 5, v);
			bitIndex += 5;
			inIndex++;
		}
		if (padding == 0)
		{
			byte v = base32DecodeMap[pszIn[inIndex]];
			setBitsValue(out, bitIndex, 5, v);
		}
		else
		{
			byte v = base32DecodeMap[pszIn[inIndex]];
			setLowerBitsWithTheHighBitsOfAnotherByte(out + outLength - 1, 5 - padding, v, 5);
		}
		return out;
	}
}