package uss;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.zip.Deflater;

/**
 * Builds a small synthetic USS (WinUAE "ASF" savestate) for tests, so no snapshot of real software is needed.
 * 
 * Chunk layout (see WinUAE savestate.cpp): 4 character name, length (including these 12 header bytes), flags
 * (bit 0 = zlib compressed, then a longword with the uncompressed size follows), payload. WinUAE aligns the next
 * chunk with 4 - (length & 3) padding bytes, i.e. 4 bytes if the length is already aligned.
 */
public class UssTestFile {

	public static final int CHIP_SIZE = 4096;
	public static final int FAST_SIZE = 1024;
	public static final int BOGO_SIZE = 512;
	public static final int FAST_ADDRESS = 0x200000;
	public static final int ROM_ADDRESS = 0xF80000;
	public static final int ROM_SIZE = 0x80000;
	public static final int PC = 0x1234;

	/** Content of the chip RAM (stored compressed in the file) */
	public static byte[] chipContent() {
		return pattern(CHIP_SIZE, 7);
	}

	/** Content of the fast RAM (stored uncompressed in the file) */
	public static byte[] fastContent() {
		return pattern(FAST_SIZE, 11);
	}

	private static byte[] pattern(int size, int step) {
		var data = new byte[size];
		for (int i = 0; i < size; i++) {
			data[i] = (byte) (i * step + (i >> 8));
		}
		return data;
	}

	public static byte[] create() {
		var out = new ByteArrayOutputStream();
		
		// Header: 4 bytes, then three zero-terminated strings
		write(out, "ASF ", false, ascii("\0\0\0\0TestEmu\0" + "1.0\0" + "synthetic test snapshot\0"));
		
		// CPU: model, flags, D0-D7, A0-A6, PC
		var cpu = ByteBuffer.allocate(4 + 4 + 16 * 4).order(ByteOrder.BIG_ENDIAN);
		cpu.putInt(0x28000);   // model
		cpu.putInt(0x1);       // flags
		for (int i = 0; i < 15; i++) {
			cpu.putInt(0x1000 + i);
		}
		cpu.putInt(PC);
		write(out, "CPU ", false, cpu.array());
		
		// Custom chip registers: flags, registers 0x000-0x09F, 0x0E0-0x11F and 0x180-0x1FF
		var chip = new byte[4 + 0xa0 + (0x120 - 0xe0) + (0x200 - 0x180)];
		for (int i = 4; i < chip.length; i++) {
			chip[i] = (byte) (0xC0 + (i & 0x3f));
		}
		write(out, "CHIP", false, chip);
		
		// Sprite 1: pointer (4 bytes) and the following 8 bytes of definition
		var sprite = new byte[12];
		for (int i = 0; i < sprite.length; i++) {
			sprite[i] = (byte) (0x41 + i);
		}
		write(out, "SPR1", false, sprite);
		
		// ROM: start, size, ... id at offset 20
		var rom = ByteBuffer.allocate(21 + 9).order(ByteOrder.BIG_ENDIAN);
		rom.putInt(ROM_ADDRESS);
		rom.putInt(ROM_SIZE);
		rom.position(20);
		rom.put(ascii("TestROM\0\0"));
		write(out, "ROM ", false, rom.array());
		
		// Expansion: the address of the first fast RAM block, then z3 address, gfx, rtarea and the second fast RAM block
		var expansion = ByteBuffer.allocate(5 * 4).order(ByteOrder.BIG_ENDIAN);
		expansion.putInt(FAST_ADDRESS);
		write(out, "EXPA", false, expansion.array());
		
		write(out, "CRAM", true, chipContent());
		write(out, "FRAM", false, fastContent());
		write(out, "BRAM", false, pattern(BOGO_SIZE, 3));
		
		write(out, "END ", false, new byte[0]);
		return out.toByteArray();
	}
	
	private static byte[] ascii(String text) {
		return text.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
	}

	private static void write(ByteArrayOutputStream out, String name, boolean compress, byte[] payload) {
		byte[] body = payload;
		int length;
		int alignedLength;
		if (compress) {
			var deflater = new Deflater();
			deflater.setInput(payload);
			deflater.finish();
			var buffer = new byte[payload.length * 2 + 64];
			int compressedLength = deflater.deflate(buffer);
			deflater.end();
			body = java.util.Arrays.copyOf(buffer, compressedLength);
			length = 4 + compressedLength;
			alignedLength = compressedLength;
		} else {
			length = payload.length;
			alignedLength = payload.length;
		}
		
		var header = ByteBuffer.allocate(compress ? 16 : 12).order(ByteOrder.BIG_ENDIAN);
		header.put(ascii(name));
		header.putInt(12 + length);
		header.putInt(compress ? 1 : 0);
		if (compress) {
			header.putInt(payload.length);
		}
		out.writeBytes(header.array());
		out.writeBytes(body);
		out.writeBytes(new byte[4 - (alignedLength & 3)]);
	}
}
