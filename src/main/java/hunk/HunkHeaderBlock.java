package hunk;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

class HunkHeaderBlock extends HunkBlock {

	private List<Integer> hunkTable;
	private List<Integer> memoryFlagsTable = new ArrayList<>();

	HunkHeaderBlock(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		super(HunkType.HUNK_HEADER, reader);
		
		parse(reader, isExecutable);
		calcHunkSize(reader);
	}
	
	@Override
	void parse(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		hunkTable = new ArrayList<>();
		
		while (true) {
			try {
				String name = HunkBlock.readName(reader);
				
				if (name == null) {
					throw new IOException();
				} else if (name.length() == 0) {
					break;
				}

			} catch (IOException e) {
				throw new HunkParseError("Error parsing HUNK_HEADER names");
			}
		}
		
		try {
			int tableSize = reader.readNextInt();
			int firstHunk = reader.readNextInt();
			int lastHunk = reader.readNextInt();
			
			if (tableSize < 0 || firstHunk < 0 || lastHunk < 0) {
				throw new HunkParseError("HUNK_HEADER invalid table_size or first_hunk or last_hunk");
			}
			
			for (int a = 0; a < lastHunk - firstHunk + 1; ++a) {
				// The upper two bits of the size are the memory type (1 = CHIP, 2 = FAST). If both are set,
				// another longword with the actual memory attributes (MEMF_*) follows.
				int hunkSize = reader.readNextInt();
				int memoryFlags = hunkSize >>> 30;
				if (memoryFlags == HunkSegment.MEMORY_EXTENDED) {
					// The exact MEMF_* attributes are not evaluated
					reader.readNextInt();
				}
				hunkTable.add(hunkSize & 0x3FFFFFFF);
				memoryFlagsTable.add(memoryFlags);
			}
		} catch (IOException e) {
			throw new HunkParseError(e);
		}
	}

	/**
	 * Memory type per hunk (MEMORY_*)
	 */
	Integer[] getMemoryFlags() {
		return memoryFlagsTable.toArray(Integer[]::new);
	}
	
	Integer[] getHunkTable() {
		return hunkTable.toArray(Integer[]::new);
	}
}
