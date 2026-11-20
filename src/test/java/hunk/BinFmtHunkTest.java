package hunk;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.junit.Test;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;

public class BinFmtHunkTest {

	private static final int HUNK_CODE = 0x3E9;
	private static final int HUNK_BSS = 0x3EB;
	private static final int HUNK_RELOC32 = 0x3EC;
	private static final int HUNK_END = 0x3F2;
	private static final int HUNK_HEADER = 0x3F3;
	
	private static final int CHIP = 0x40000000;
	private static final int FAST = 0x80000000;
	
	/**
	 * Builds a hunk executable:
	 * Hunk 0: code with 2 longwords (chip RAM), one reloc to hunk 1 at offset 4
	 * Hunk 1: BSS with 1 longword (fast RAM)
	 * Hunk 2: BSS with 1 longword, both memory bits set (followed by a longword with the attributes)
	 */
	private byte[] createExecutable() {
		var b = ByteBuffer.allocate(256).order(ByteOrder.BIG_ENDIAN);
		b.putInt(HUNK_HEADER);
		b.putInt(0);                 // no resident libraries
		b.putInt(3);                 // table size
		b.putInt(0);                 // first hunk
		b.putInt(2);                 // last hunk
		b.putInt(CHIP | 2);
		b.putInt(FAST | 1);
		b.putInt(CHIP | FAST | 1);
		b.putInt(0x00000005);        // MEMF_* attributes of the third hunk
		
		b.putInt(HUNK_CODE);
		b.putInt(2);
		b.putInt(0x4E714E71);        // nop nop
		b.putInt(0x00000010);        // longword that is relocated
		b.putInt(HUNK_RELOC32);
		b.putInt(1);                 // one offset ...
		b.putInt(1);                 // ... to hunk 1
		b.putInt(4);                 // at offset 4
		b.putInt(0);                 // end of the reloc list
		b.putInt(HUNK_END);
		
		b.putInt(HUNK_BSS);
		b.putInt(1);
		b.putInt(HUNK_END);
		
		b.putInt(HUNK_BSS);
		b.putInt(1);
		b.putInt(HUNK_END);
		
		var bytes = new byte[b.position()];
		b.rewind();
		b.get(bytes);
		return bytes;
	}
	
	private BinImage load(byte[] bytes) throws Exception {
		var reader = new BinaryReader(new ByteArrayProvider(bytes), false);
		var file = new HunkBlockFile(reader, true);
		var image = BinFmtHunk.loadImage(file, new MessageLog());
		assertNotNull(image);
		return image;
	}
	
	@Test
	public void memoryFlagsAreNotPartOfTheSize() throws Exception {
		var segments = load(createExecutable()).getSegments();
		assertEquals(3, segments.length);
		assertEquals("Chip flag must not be part of the size", 8, segments[0].getSize());
		assertEquals("Fast flag must not be part of the size (and not rejected as negative size)", 4, segments[1].getSize());
		assertEquals("Extended memory attributes are skipped", 4, segments[2].getSize());
	}
	
	@Test
	public void memoryTypeIsKeptPerHunk() throws Exception {
		var segments = load(createExecutable()).getSegments();
		assertEquals(HunkSegment.MEMORY_CHIP, segments[0].getSegmentInfo().getMemoryFlags());
		assertEquals(HunkSegment.MEMORY_FAST, segments[1].getSegmentInfo().getMemoryFlags());
		assertEquals(HunkSegment.MEMORY_EXTENDED, segments[2].getSegmentInfo().getMemoryFlags());
	}
	
	@Test
	public void segmentTypesAndRelocations() throws Exception {
		var segments = load(createExecutable()).getSegments();
		assertEquals(SegmentType.SEGMENT_TYPE_CODE, segments[0].getType());
		assertEquals(SegmentType.SEGMENT_TYPE_BSS, segments[1].getType());
		assertArrayEquals(new byte[] { 0x4E, 0x71, 0x4E, 0x71, 0, 0, 0, 0x10 }, segments[0].getOriginalData());
		assertNull("BSS has no data in the file", segments[1].getOriginalData());
		
		var targets = segments[0].getRelocationsToSegments();
		assertEquals(1, targets.length);
		assertEquals(segments[1], targets[0]);
		var relocations = segments[0].getRelocations(targets[0]);
		assertEquals(1, relocations.length);
		assertEquals(4, relocations[0].getOffset());
		assertEquals(4, relocations[0].getWidth());
	}
	
	@Test
	public void relocationIsAppliedToTheTargetHunkAddress() throws Exception {
		var image = load(createExecutable());
		var relocate = new Relocate(image);
		var addresses = relocate.getSeqAddresses(0x1000);
		assertEquals(0x1000, addresses[0]);
		assertEquals(0x1008, addresses[1]);
		
		var data = relocate.relocate(addresses).get(0);
		// The longword at offset 4 (0x10) is moved by the address of hunk 1
		assertEquals(0x1008 + 0x10, ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN).getInt(4));
	}
	
	@Test
	public void unknownHunkTypeIsReported() {
		var b = ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN);
		b.putInt(HUNK_HEADER);
		b.putInt(0);
		b.putInt(0x7777);   // not a valid hunk type
		try {
			new HunkBlockFile(new BinaryReader(new ByteArrayProvider(b.array()), false), true);
			fail("Expected HunkParseError");
		} catch (HunkParseError expected) {
			// ok
		}
	}
}
