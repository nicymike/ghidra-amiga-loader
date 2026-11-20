package uss;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;

import org.junit.Test;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;

public class UssTest {

	private static UssFile load(byte[] data) throws Exception {
		return new UssFile(new BinaryReader(new ByteArrayProvider(data), false), null, null);
	}

	private static UssFile.MemoryRegion block(UssFile uss, String name) {
		var block = uss.memBlocks.stream().filter(b -> b.name.equals(name)).findFirst().orElse(null);
		assertNotNull("memory block " + name, block);
		return block;
	}

	@Test
	public void recognizesUssFiles() {
		assertTrue(UssFile.isUssFile(new BinaryReader(new ByteArrayProvider(UssTestFile.create()), false)));
		assertFalse(UssFile.isUssFile(new BinaryReader(new ByteArrayProvider(new byte[64]), false)));
	}

	@Test
	public void readsEmulatorInformation() throws Exception {
		var uss = load(UssTestFile.create());
		assertEquals("TestEmu", uss.emuName);
		assertEquals("1.0", uss.emuVersion);
		assertEquals("synthetic test snapshot", uss.description);
		assertEquals("TestROM", uss.romId);
	}

	@Test
	public void readsCpuState() throws Exception {
		var uss = load(UssTestFile.create());
		assertEquals(0x28000, uss.cpuModel);
		assertEquals(1, uss.cpuFlags);
		// D0-D7, A0-A6, then the PC
		assertEquals(0x1000, uss.registers[0]);
		assertEquals(0x100E, uss.registers[14]);
		assertEquals(UssTestFile.PC, uss.registers[15]);
	}

	@Test
	public void readsMemoryRegionsWithTheirAddresses() throws Exception {
		var uss = load(UssTestFile.create());
		
		// The chip RAM is stored zlib-compressed in the file
		var chip = block(uss, "CHIP");
		assertEquals(0, chip.start);
		assertEquals(UssTestFile.CHIP_SIZE, chip.length);
		assertArrayEquals(UssTestFile.chipContent(), chip.content);
		
		// Fast RAM goes to the address from the expansion chunk
		var fast = block(uss, "FRAM0");
		assertEquals(UssTestFile.FAST_ADDRESS, fast.start);
		assertArrayEquals(UssTestFile.fastContent(), fast.content);
		
		var bogo = block(uss, "BOGO");
		assertEquals(0xC00000, bogo.start);
		assertEquals(UssTestFile.BOGO_SIZE, bogo.length);
		
		// The ROM is not part of a snapshot: only its position and size are known
		var rom = block(uss, "ROM");
		assertEquals(UssTestFile.ROM_ADDRESS, rom.start);
		assertEquals(UssTestFile.ROM_SIZE, rom.length);
		assertNull(rom.content);
		
		var custom = block(uss, "Custom");
		assertEquals(0xdff000, custom.start);
		assertEquals(0x200, custom.length);
	}

	@Test
	public void copiesCustomChipAndSpriteRegisters() throws Exception {
		var custom = block(load(UssTestFile.create()), "Custom").content;
		
		// The chip chunk starts with the chipset flags (4 bytes), then follow the registers 0x000-0x09F
		assertEquals((byte) (0xC0 + (4 & 0x3f)), custom[0]);
		assertEquals((byte) (0xC0 + ((4 + 0x9f) & 0x3f)), custom[0x9f]);
		// 0x0A0-0x0DF are not saved
		assertEquals(0, custom[0xa0]);
		
		// Sprite 1: SPR1PT at 0x124, SPR1POS/CTL/DATA/DATB at 0x148
		assertArrayEquals(new byte[] { 0x41, 0x42, 0x43, 0x44 }, java.util.Arrays.copyOfRange(custom, 0x124, 0x128));
		assertArrayEquals(new byte[] { 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c }, java.util.Arrays.copyOfRange(custom, 0x148, 0x150));
	}

	@Test
	public void rejectsFilesWithoutAsfMarker() {
		try {
			load(new byte[64]);
			fail("Expected IOException");
		} catch (IOException expected) {
			// ok
		} catch (Exception other) {
			fail("Expected IOException but got " + other);
		}
	}
}
