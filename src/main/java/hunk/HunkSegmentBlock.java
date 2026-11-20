package hunk;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

class HunkSegmentBlock extends HunkBlock {
	
	private byte[] data = null;
	private int sizeLongs = 0;
	
	HunkSegmentBlock(HunkType type, BinaryReader reader, boolean isExecutable) throws HunkParseError {
		super(type, reader);

		parse(reader, isExecutable);
		calcHunkSize(reader);
	}
	
	@Override
	void parse(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		try {
			// The upper two bits are memory flags (see HUNK_HEADER) and not part of the size
			int size = sizeLongs = reader.readNextInt() & 0x3FFFFFFF;
			
			if (super.getHunkType() != HunkType.HUNK_BSS) {
				size *= 4;
				data = reader.readNextByteArray(size);
			}
		} catch (IOException e) {
			throw new HunkParseError(e);
		}
	}

    void setSizeLongs(int sizeLongs) {
		this.sizeLongs = sizeLongs;
	}
	
	byte[] getData() {
		return this.data;
	}

    int getSizeLongs() {
		return this.sizeLongs;
	}
}
