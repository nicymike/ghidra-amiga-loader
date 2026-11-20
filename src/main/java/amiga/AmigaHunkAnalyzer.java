/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package amiga;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.List;

import fd.FdFunction;
import fd.FdFunctionsInLibs;
import fd.FdLibFunctions;
import fd.FdParser;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class AmigaHunkAnalyzer extends AbstractAnalyzer {
	//private static final int imageBaseOffset = 0x10000;
	private final List<String> filter = new ArrayList<String>();
	private FdFunctionsInLibs funcsList;
	private LibraryCallResolver resolver;
	private Program resolverProgram;
	private final Set<Address> unresolvedCalls = new TreeSet<>();
	private final Set<String> reportedMissingLibraries = new HashSet<>();
	
	public AmigaHunkAnalyzer() {
		super("Amiga Library Calls", "Analyses calls to system libraries", AnalyzerType.INSTRUCTION_ANALYZER);
		
		filter.add(FdParser.EXEC_LIB);
		filter.add(FdParser.DOS_LIB);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return program.getExecutableFormat().contains("Amiga") && !program.getExecutableFormat().contains("Kickstart");
	}

	@Override
	public boolean canAnalyze(Program program) {
		if(program.getLanguage().getProcessor().toString().equals("68000")) {
			funcsList = FdFunctionsInLibs.getInstance();
			return true;
		}
		funcsList = null;
		return false;
	}
	
	@Override
	public void registerOptions(Options options, Program program) {
		if (funcsList == null) {
			return;
		}

		String[] libsList = funcsList.getLibsList(null);
		for (String lib : libsList) {
			boolean defaultValue = filter.contains(lib);
			options.registerOption(lib, defaultValue, null, String.format("Analyze calls from %s", lib));
		}
	}
	
	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);

		if (funcsList == null) {
			return;
		}
		
		filter.clear();
		
		String[] libsList = funcsList.getLibsList(filter);
		for (String lib : libsList) {
			if (options.getBoolean(lib, false)) {
				filter.add(lib);
			}
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		// The analyzer is called several times with the newly found instructions. What is known about opened
		// libraries is therefore kept across the calls.
		if (resolver == null || resolverProgram != program) {
			resolver = new LibraryCallResolver(program);
			resolverProgram = program;
			unresolvedCalls.clear();
			reportedMissingLibraries.clear();
		}
		
		monitor.setMessage("Searching for opened libraries...");
		resolver.scanOpenLibraryCalls(set, monitor);
		
		// The libraries from the options and all libraries the program opens with OpenLibrary
		var libraries = new ArrayList<String>();
		for (var lib : filter) {
			if (funcsList.findLibIndex(lib) != -1 && !libraries.contains(lib)) {
				libraries.add(lib);
			}
		}
		for (var opened : resolver.getOpenedLibraries()) {
			if (funcsList.findLibIndex(opened) == -1) {
				if (reportedMissingLibraries.add(opened)) {
					log.appendMsg(String.format("No function table for opened library '%s'", opened));
				}
			} else if (!libraries.contains(opened)) {
				libraries.add(opened);
			}
		}
		
		monitor.setMessage("Creating library functions...");
		
		FlatProgramAPI fpa = new FlatProgramAPI(program);
		try {
			var fdm = fpa.openDataTypeArchive(Application.getModuleDataFile("amiga_ndk39.gdt").getFile(false), true);
			for (String lib : libraries) {
				createFunctionsSegment(fpa, fdm, lib, funcsList.getFunctionTableByLib(lib), log);
			}
		} catch (Exception e) {
			log.appendException(e);
			return false;
		}
		
		monitor.setMessage("Analysing library calls...");

		FunctionIterator fiter = program.getFunctionManager().getFunctions(set, true);
		while (fiter.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}

			Function func = fiter.next();
			Address start = func.getEntryPoint();
			
			SymbolicPropogator symEval = new SymbolicPropogator(program);
			symEval.setParamRefCheck(true);
			symEval.setReturnRefCheck(true);
			symEval.setStoredRefCheck(true);

			try {
				symEval.flowConstants(start, func.getBody(), new ConstantPropagationContextEvaluator(monitor, true), true, monitor);
			} catch (CancelledException e) {
				log.appendException(e);
				return false;
			}
		}
		
		// The new calls and the ones that could not be assigned earlier, as more may be known by now
		// (New code can also complete a path that was cut off at a function entry without caller)
		var calls = new TreeSet<Address>(unresolvedCalls);
		for (var instruction : program.getListing().getInstructions(set, true)) {
			if (LibraryCallResolver.getLibraryCall(instruction) != null) {
				calls.add(instruction.getAddress());
			}
		}
		
		int resolved = 0;
		for (var address : calls) {
			if (monitor.isCancelled()) {
				break;
			}
			var instruction = program.getListing().getInstructionAt(address);
			var call = instruction != null ? LibraryCallResolver.getLibraryCall(instruction) : null;
			if (call == null) {
				unresolvedCalls.remove(address);
			} else if (annotateLibraryCall(program, instruction, call, resolver, libraries)) {
				unresolvedCalls.remove(address);
				resolved++;
			} else {
				unresolvedCalls.add(address);
			}
		}
		
		if (resolved > 0) {
			String summary = String.format("Amiga Library Calls: %d library calls assigned, %d not assignable so far (libraries opened by the program: %s)",
				resolved, unresolvedCalls.size(), resolver.getOpenedLibraries());
			if (unresolvedCalls.isEmpty()) {
				// Only informational: logging it to the MessageLog would pop up the "warnings/errors" dialog
				Msg.info(this, summary);
			} else {
				log.appendMsg(summary);
			}
		}
		return true;
	}
	
	/**
	 * Points the call to the function of the library.
	 * 
	 * The library is determined from A6. If that is not possible there is no assignment, because the same
	 * offset means something different in every library.
	 * 
	 * @return true if the call was assigned to a function
	 */
	private boolean annotateLibraryCall(Program program, Instruction instruction, LibraryCallResolver.LibraryCall call, LibraryCallResolver resolver, List<String> libraries) {
		var library = resolver.resolveLibrary(instruction);
		if (library == null || !libraries.contains(library)) {
			return false;
		}
		FdFunction function = findFunction(library, call.lvo());
		if (function == null) {
			return false;
		}
		
		MemoryBlock libMemory = program.getMemory().getBlock(function.getLib());
		if (libMemory == null) {
			return false;
		}
		Address funcStart = libMemory.getStart().add(Math.abs(function.getBias()));
		if (!libMemory.contains(funcStart)) {
			return false;
		}
		
		int operand = call.operandIndex();
		Reference primaryRef = instruction.getPrimaryReference(operand);
		instruction.addOperandReference(operand, funcStart, RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS);
		
		if (((null == primaryRef) || (SourceType.ANALYSIS == primaryRef.getSource())) &&
				!function.isPrivate() && function.getLib().equals(FdParser.EXEC_LIB)) {
			for (Reference ref : instruction.getOperandReferences(operand)) {
				if (funcStart.equals(ref.getToAddress())) {
					instruction.setPrimaryMemoryReference(ref);
					break;
				}
			}
		}
		return true;
	}
	
	private FdFunction findFunction(String library, int lvo) {
		var functions = funcsList.getLibsFunctionsByBias(List.of(library), lvo);
		return functions.length > 0 ? functions[0] : null;
	}
	
	/**
	 * Ghidra data type for a C type from the SFD files (e.g. "struct Library *", "UBYTE *", "ULONG").
	 * 
	 * Unknown types become a pointer or a 32-bit value, so that a single unknown type does not prevent
	 * the whole library.
	 */
	private static DataType getAmigaDataType(String type, FileDataTypeManager fdm) {
		type = type.replace("struct ", "");
		type = type.replace("const ", "");
		type = type.replace("CONST ", "");
		type = type.replace("volatile ", "");
		type = type.replace("VOLATILE ", "");
		if (type.contains("(")) {
			return new PointerDataType(new FunctionDefinitionDataType("FUNC")); // TODO: correct function pointer type
		}
		
		DataType baseType = null;
		int pointerLevels = 0;
		for (var word : type.trim().split("\\s+")) {
			if (word.isEmpty()) {
				continue;
			}
			if (word.matches("\\*+")) {
				pointerLevels += word.length();
			} else {
				var list = new ArrayList<DataType>();
				fdm.findDataTypes(word, list);
				baseType = !list.isEmpty() ? list.get(0) : null;
			}
		}
		
		if (baseType == null) {
			// Unknown type: pointer if it is supposed to be one, otherwise a 32-bit value (one register)
			return pointerLevels > 0 ? PointerDataType.dataType : Undefined4DataType.dataType;
		}
		DataType dataType = baseType;
		for (int i = 0; i < pointerLevels; i++) {
			dataType = new PointerDataType(dataType);
		}
		return dataType;
	}

	/** Memory blocks from here on are hardware (CIA, custom chips) and not part of the program */
	private static final long HARDWARE_START = 0xBF0000L;
	
	/**
	 * The first aligned address after all blocks of the program. The library blocks are placed there one after
	 * the other.
	 */
	private static Address findFreeLibraryAddress(FlatProgramAPI fpa, long align) {
		long end = 0;
		for (MemoryBlock memBlock : fpa.getMemoryBlocks()) {
			if (memBlock.getStart().getOffset() < HARDWARE_START) {
				end = Math.max(end, memBlock.getEnd().getOffset());
			}
		}
		long start = ((end + align) / align) * align;
		return fpa.toAddr(start);
	}
	
	private static void createFunctionsSegment(FlatProgramAPI fpa, FileDataTypeManager fdm, String lib, FdLibFunctions funcs, MessageLog log) throws InvalidInputException, DuplicateNameException, CodeUnitInsertionException {
		if ((null == funcs) || (fpa.getMemoryBlock(lib) != null)) {
			return;
		}
		FdFunction[] funcArr = funcs.getFunctions();
		long segAlign = 0x1000;
		long segSize = 6 * 7;  // room for the standard functions of a device (the largest standard library)
		for (FdFunction func : funcArr) {
			segSize = Math.max(segSize, Math.abs(func.getBias()) + 6);
		}
		segSize = ((segSize + (segAlign - 1)) / segAlign) * segAlign;
		Address segAddr = findFreeLibraryAddress(fpa, segAlign);
		
		AmigaUtils.createSegment(null, fpa, lib, segAddr.getOffset(), segSize, true, true, log);
		
		for (FdFunction func : funcArr) {
			try {
				createLibraryFunction(fpa, fdm, segAddr, func, log);
			} catch (Exception e) {
				// A faulty prototype must not prevent the remaining functions of the library
				log.appendMsg(String.format("Could not create %s: %s", func.getName(true), e));
			}
		}
	}
	
	private static void createLibraryFunction(FlatProgramAPI fpa, FileDataTypeManager fdm, Address segAddr, FdFunction func, MessageLog log) throws Exception {
		Address funcAddress = segAddr.add(Math.abs(func.getBias()));
		AmigaUtils.setFunction(fpa, funcAddress, func.getName(true).replace(FdFunction.LIB_SPLITTER, "_"), log);
		Function function = fpa.getFunctionAt(funcAddress);
		function.setCustomVariableStorage(true);

		List<ParameterImpl> params = new ArrayList<>();
		Program program = fpa.getCurrentProgram();
		for (var arg : func.getArgs()) {
			var dataType = getAmigaDataType(arg.type, fdm);
			params.add(new ParameterImpl(arg.name, dataType, program.getRegister(arg.reg), program));
		}

		var retType = func.getReturnType();
		var returnValue = retType.equals("VOID") ? new ReturnParameterImpl(VoidDataType.dataType, VariableStorage.VOID_STORAGE, program) : new ReturnParameterImpl(getAmigaDataType(retType, fdm), program.getRegister("D0"), program);
		function.updateFunction(null, returnValue, FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS, params.toArray(ParameterImpl[]::new));
		DataUtilities.createData(program, funcAddress, new ArrayDataType(ByteDataType.dataType, 6, -1), -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
	}
}
