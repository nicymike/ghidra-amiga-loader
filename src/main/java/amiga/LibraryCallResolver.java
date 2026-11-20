package amiga;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import fd.FdParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.task.TaskMonitor;

/**
 * Determines which library a call of the form <code>jsr -552(a6)</code> addresses.
 *
 * The library base is in A6. The register is followed backwards heuristically up to its last assignment:
 * <ul>
 * <li><code>movea.l (4).w,a6</code> is the ExecBase.</li>
 * <li><code>movea.l d0,a6</code> directly after <code>OpenLibrary</code> is the library that was just opened.</li>
 * <li><code>movea.l (var),a6</code> is the library that <code>OpenLibrary</code> stored in <code>var</code> earlier.</li>
 * </ul>
 * The resolver reads the name of the opened library from the string the code loads into A1 before
 * <code>OpenLibrary</code>.
 */
class LibraryCallResolver {

	static final int LVO_OPEN_LIBRARY = -552;
	static final int LVO_OLD_OPEN_LIBRARY = -408;

	/** Number of instructions that are searched backwards. */
	private static final int LOOKBACK = 64;
	/** Maximum number of instructions examined when searching along the control flow. */
	private static final int MAX_STEPS = 2000;
	/** Number of instructions after OpenLibrary that are searched for the store of the result. */
	private static final int LOOKAHEAD = 8;
	/** Marker: A6 gets a constant (not a library base) */
	private static final String CONSTANT = "<constant>";
	/** Marker for a variable that holds different libraries at different places */
	private static final String AMBIGUOUS = "<ambiguous>";
	private static final int MAX_NAME_LENGTH = 48;

	/** A call of a library function through an offset relative to A6 */
	record LibraryCall(int lvo, int operandIndex) {
	}

	private final Program program;
	private final Map<String, String> libraryBases = new HashMap<>();
	private final Set<String> openedLibraries = new TreeSet<>();
	/** Increased whenever the resolver learns something new (opened libraries, base variables) */
	private int knowledgeVersion;

	LibraryCallResolver(Program program) {
		this.program = program;
	}

	/**
	 * Searches the OpenLibrary calls in the instructions of the set (null: in the whole program) and remembers the
	 * names of the libraries and the variables in which the base addresses are stored.
	 */
	void scanOpenLibraryCalls(AddressSetView set, TaskMonitor monitor) {
		var instructions = set != null ? program.getListing().getInstructions(set, true) : program.getListing().getInstructions(true);
		for (var instruction : instructions) {
			if (monitor.isCancelled()) {
				return;
			}
			rememberExecBaseCopy(instruction);
			var call = getLibraryCall(instruction);
			if (call == null || !isOpenLibrary(call.lvo())) {
				continue;
			}
			var library = getOpenedLibrary(instruction);
			if (library == null) {
				continue;
			}
			if (openedLibraries.add(library)) {
				knowledgeVersion++;
			}
			rememberLibraryBase(instruction, library);
		}
	}

	/**
	 * @return a number that changes whenever the resolver learned something new; calls that could not be
	 * resolved before only need another try if it changed
	 */
	int getKnowledgeVersion() {
		return knowledgeVersion;
	}

	/**
	 * @return the names of all libraries (e.g. "dos_library") that the program opens with OpenLibrary
	 */
	Set<String> getOpenedLibraries() {
		return openedLibraries;
	}

	/**
	 * @return the call if the instruction is a jsr/jmp with an offset relative to A6, otherwise null
	 */
	static LibraryCall getLibraryCall(Instruction instruction) {
		var mnemonic = instruction.getMnemonicString();
		if (!mnemonic.equals("jsr") && !mnemonic.equals("jmp")) {
			return null;
		}
		// Depending on the language definition, "(-552,A6)" is one operand or spread over several
		for (int i = 0; i < instruction.getNumOperands(); i++) {
			boolean hasA6 = false;
			Scalar offset = null;
			for (var object : instruction.getOpObjects(i)) {
				if (object instanceof Register register && register.getName().equals("A6")) {
					hasA6 = true;
				} else if (object instanceof Scalar scalar) {
					offset = scalar;
				}
			}
			if (hasA6 && offset != null && offset.getSignedValue() < 0) {
				return new LibraryCall((int) offset.getSignedValue(), i);
			}
		}
		return null;
	}

	/**
	 * Determines the library that A6 holds at the call.
	 * 
	 * The control flow is followed backwards up to the assignments to A6, also across jumps and into
	 * calling functions (assumption: subroutines preserve A6). The result is only valid if every path ends
	 * in an assignment whose library is known, and all of them name the same library. Paths that end without
	 * assignment, assignments from unknown sources and exceeding the search limit make the result unknown.
	 * Assignments of constants (e.g. A6 = custom chip base) do not count, because a library call cannot happen
	 * through them.
	 * 
	 * @return name of the library (e.g. "exec_library") or null if it cannot be determined unambiguously
	 */
	String resolveLibrary(Instruction call) {
		var libraries = new TreeSet<String>();
		boolean unknown = false;
		
		var visited = new HashSet<Address>();
		var work = new ArrayDeque<Instruction>();
		work.add(call);
		visited.add(call.getAddress());
		
		int steps = 0;
		while (!work.isEmpty()) {
			if (steps++ >= MAX_STEPS) {
				return null;
			}
			var current = work.poll();
			var predecessors = getPredecessors(current);
			if (predecessors.isEmpty()) {
				// Nothing leads here (function entry without known caller): A6 is not known at this path
				unknown = true;
			}
			for (var predecessor : predecessors) {
				if (!visited.add(predecessor.getAddress())) {
					continue;
				}
				if (!writesRegister(predecessor, "A6")) {
					work.add(predecessor);
					continue;
				}
				var library = resolveA6Source(predecessor);
				if (library == null) {
					unknown = true;
				} else if (!CONSTANT.equals(library)) {
					libraries.add(library);
				}
			}
		}
		
		if (unknown || libraries.size() != 1) {
			return null;
		}
		return libraries.first();
	}
	
	/**
	 * The instructions from which the execution can reach this instruction: the previous one if it falls
	 * through, and all jumps and calls to here.
	 */
	private List<Instruction> getPredecessors(Instruction instruction) {
		var predecessors = new ArrayList<Instruction>();
		
		var previous = instruction.getPrevious();
		if (previous != null && instruction.getAddress().equals(previous.getFallThrough())) {
			predecessors.add(previous);
		}
		
		var references = program.getReferenceManager().getReferencesTo(instruction.getAddress());
		while (references.hasNext()) {
			var reference = references.next();
			if (!reference.getReferenceType().isFlow()) {
				continue;
			}
			var source = program.getListing().getInstructionAt(reference.getFromAddress());
			if (source != null && !source.getAddress().equals(instruction.getAddress())) {
				predecessors.add(source);
			}
		}
		return predecessors;
	}
	
	/**
	 * @return the name of the library that the assignment puts into A6, {@link #CONSTANT} for assigning a constant
	 * (not a library base), or null if unknown (including restoring A6 from the stack)
	 */
	private String resolveA6Source(Instruction assignment) {
		var mnemonic = assignment.getMnemonicString();
		if (mnemonic.equals("lea") || mnemonic.startsWith("lea.")) {
			return CONSTANT;
		}
		if (mnemonic.startsWith("movem")) {
			// Could restore A6 from the stack or load any value from memory: the value cannot be followed
			return null;
		}
		if (!isMove(mnemonic) || assignment.getNumOperands() != 2) {
			return null;
		}

		var source = assignment.getOpObjects(0);
		if (source.length == 1 && source[0] instanceof Scalar) {
			// movea.l #const,a6
			return CONSTANT;
		}
		if (source.length == 1 && source[0] instanceof Register register) {
			if (register.getName().equals("D0")) {
				// movea.l d0,a6: result of the OpenLibrary call directly before
				return getOpenedLibraryByPreviousCall(assignment);
			}
			// From another register: cannot be followed
			return null;
		}
		
		var address = getMemoryAddress(assignment, 0);
		if (address != null && address == 4) {
			return FdParser.EXEC_LIB;
		}
		var key = getKey(assignment, 0);
		var library = key != null ? libraryBases.get(key) : null;
		return AMBIGUOUS.equals(library) ? null : library;
	}

	/**
	 * The library that the OpenLibrary call directly before the instruction opened, provided D0 is not
	 * changed in between.
	 */
	private String getOpenedLibraryByPreviousCall(Instruction instruction) {
		var current = instruction;
		for (int i = 0; i < LOOKBACK; i++) {
			var previous = current.getPrevious();
			if (previous == null || previous.getFlowType().isTerminal()) {
				return null;
			}
			current = previous;
			var call = getLibraryCall(previous);
			if (call != null) {
				return isOpenLibrary(call.lvo()) ? getOpenedLibrary(previous) : null;
			}
			if (previous.getFlowType().isCall() || writesRegister(previous, "D0")) {
				// D0 holds the result of something else
				return null;
			}
		}
		return null;
	}

	/**
	 * Name of the library that the OpenLibrary call opens, from the name string in A1
	 */
	private String getOpenedLibrary(Instruction openLibraryCall) {
		var current = openLibraryCall;
		for (int i = 0; i < LOOKBACK; i++) {
			var previous = current.getPrevious();
			if (previous == null || previous.getFlowType().isTerminal()) {
				return null;
			}
			current = previous;
			if (!writesRegister(previous, "A1")) {
				continue;
			}

			var address = getNameAddress(previous);
			if (address == null) {
				return null;
			}
			var name = readString(address);
			if (name == null || !name.toLowerCase().endsWith(".library")) {
				return null;
			}
			return toLibraryKey(name);
		}
		return null;
	}

	/**
	 * Address of the string that the instruction loads into A1 (lea name,a1 / movea.l #name,a1)
	 */
	private Long getNameAddress(Instruction load) {
		var mnemonic = load.getMnemonicString();
		if (load.getNumOperands() != 2) {
			return null;
		}
		if (mnemonic.equals("lea")) {
			var address = getMemoryAddress(load, 0);
			if (address != null) {
				return address;
			}
			// depending on the operand type, lea (addr).l,a1 provides the absolute address as a scalar
			var source = load.getOpObjects(0);
			if (source.length == 1 && source[0] instanceof Scalar absolute) {
				return absolute.getUnsignedValue();
			}
		}
		if (isMove(mnemonic)) {
			var source = load.getOpObjects(0);
			if (source.length == 1 && source[0] instanceof Scalar immediate) {
				return immediate.getUnsignedValue();
			}
		}
		return null;
	}

	/**
	 * Remembers variables to which the ExecBase from address 4 is copied: <code>move.l (4).l,var</code>
	 * or <code>movea.l (4).l,a0</code> followed by <code>move.l a0,var</code>.
	 */
	private void rememberExecBaseCopy(Instruction instruction) {
		if (!isMove(instruction.getMnemonicString()) || instruction.getNumOperands() != 2) {
			return;
		}
		var address = getMemoryAddress(instruction, 0);
		if (address == null || address != 4) {
			return;
		}
		
		var destination = instruction.getOpObjects(1);
		if (!(destination.length == 1 && destination[0] instanceof Register register)) {
			putLibraryBase(instruction, 1, FdParser.EXEC_LIB);
			return;
		}
		
		var current = instruction;
		for (int i = 0; i < LOOKAHEAD; i++) {
			var next = current.getNext();
			if (next == null || next.getFlowType().isTerminal()) {
				return;
			}
			current = next;
			if (isMove(next.getMnemonicString()) && next.getNumOperands() == 2) {
				var source = next.getOpObjects(0);
				if (source.length == 1 && source[0] instanceof Register copied && copied.equals(register)) {
					putLibraryBase(next, 1, FdParser.EXEC_LIB);
					return;
				}
			}
			if (writesRegister(next, register.getName())) {
				return;
			}
		}
	}
	
	private void putLibraryBase(Instruction instruction, int operand, String library) {
		var key = getKey(instruction, operand);
		if (key == null) {
			return;
		}
		var existing = libraryBases.get(key);
		var value = (existing == null || existing.equals(library)) ? library : AMBIGUOUS;
		if (!value.equals(existing)) {
			libraryBases.put(key, value);
			knowledgeVersion++;
		}
	}
	
	private void rememberLibraryBase(Instruction openLibraryCall, String library) {
		var current = openLibraryCall;
		for (int i = 0; i < LOOKAHEAD; i++) {
			var next = current.getNext();
			if (next == null) {
				return;
			}
			current = next;
			if (isMove(next.getMnemonicString()) && next.getNumOperands() == 2) {
				var source = next.getOpObjects(0);
				var destination = next.getOpObjects(1);
				boolean fromD0 = source.length == 1 && source[0] instanceof Register register && register.getName().equals("D0");
				boolean toMemory = destination.length > 0 && !(destination[0] instanceof Register && destination.length == 1);
				if (fromD0 && toMemory) {
					putLibraryBase(next, 1, library);
					return;
				}
			}
			// If D0 was overwritten or the flow branches, it is no longer the result of OpenLibrary
			if (writesRegister(next, "D0") || next.getFlowType().isCall() || next.getFlowType().isTerminal()) {
				return;
			}
		}
	}

	/**
	 * move/movea, with or without size suffix ("movea.l")
	 */
	private static boolean isMove(String mnemonic) {
		return mnemonic.equals("move") || mnemonic.startsWith("move.") || mnemonic.equals("movea") || mnemonic.startsWith("movea.");
	}
	
	private static boolean isOpenLibrary(int lvo) {
		return lvo == LVO_OPEN_LIBRARY || lvo == LVO_OLD_OPEN_LIBRARY;
	}

	/**
	 * "dos.library" becomes "dos_library" (name of the library in the SFD files)
	 */
	static String toLibraryKey(String libraryName) {
		return libraryName.toLowerCase().replace('.', '_');
	}

	private static boolean writesRegister(Instruction instruction, String registerName) {
		for (var result : instruction.getResultObjects()) {
			if (result instanceof Register register && register.getName().equals(registerName)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Key for a memory operand, so that storing to and loading from the same variable yields the same key.
	 * 
	 * These are absolute and PC-relative addresses as well as variables relative to A4/A5 (base registers
	 * for global data, whose value does not change in the program). Other operands have no key.
	 */
	private String getKey(Instruction instruction, int operand) {
		var address = getMemoryAddress(instruction, operand);
		if (address != null) {
			return String.format("A:%08X", address);
		}
		for (var object : instruction.getOpObjects(operand)) {
			if (object instanceof Register register && (register.getName().equals("A4") || register.getName().equals("A5"))) {
				return "R:" + instruction.getDefaultOperandRepresentation(operand);
			}
		}
		return null;
	}
	
	/**
	 * Effective address of a memory operand if it is constant: absolute ((addr).l, (addr).w) or
	 * PC-relative ((d16,PC)). Otherwise null.
	 */
	private Long getMemoryAddress(Instruction instruction, int operand) {
		var objects = instruction.getOpObjects(operand);
		if (objects.length == 1 && objects[0] instanceof Address address) {
			return address.getOffset();
		}
		if (objects.length == 2 && objects[0] instanceof Scalar displacement
				&& objects[1] instanceof Register register && register.getName().equals("PC")) {
			// For (d16,PC), the PC points to the extension word, i.e. two bytes after the instruction
			return instruction.getAddress().getOffset() + 2 + displacement.getSignedValue();
		}
		return null;
	}

	private String readString(long offset) {
		var memory = program.getMemory();
		var builder = new StringBuilder();
		try {
			var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
			for (int i = 0; i < MAX_NAME_LENGTH; i++) {
				int value = memory.getByte(address.add(i)) & 0xff;
				if (value == 0) {
					return builder.toString();
				}
				if (value < 0x20 || value > 0x7e) {
					return null;
				}
				builder.append((char) value);
			}
		} catch (MemoryAccessException | RuntimeException e) {
			return null;
		}
		return null;
	}
}
