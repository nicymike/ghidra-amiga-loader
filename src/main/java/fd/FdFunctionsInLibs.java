package fd;

import java.io.File;
import java.io.IOException;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map.Entry;

import ghidra.framework.Application;
import ghidra.util.Msg;

public class FdFunctionsInLibs {
	private List<FdFunction> funcsList;
	private List<String> libsList;
	private List<Entry<String, FdLibFunctions>> libFuncs;
	
	private void initList() {
		funcsList = new ArrayList<>();
		libsList = new ArrayList<>();
		libFuncs = new ArrayList<>();
		
		try {
			File dir = Application.getModuleDataSubDirectory("sfd").getFile(false);
			File[] entries = dir.listFiles();
			if (entries == null) {
				Msg.error(this, "No function tables found in " + dir);
				return;
			}
			
			for (final File entry : entries) {
				FdLibFunctions fd = FdParser.readSfdFile(entry.getName());
				if(fd != null) {
					var lname = fd.getBaseName().toLowerCase();
					libsList.add(lname);
					libFuncs.add(new AbstractMap.SimpleEntry<String, FdLibFunctions>(lname, fd));
					funcsList.addAll(Arrays.asList(fd.getFunctions()));
				}
		    }
		} catch (IOException e) {
			Msg.error(this, "Could not read the function tables: " + e.getMessage(), e);
		}
	}
	
	private static FdFunctionsInLibs instance;
	
	/**
	 * The function tables are read from about 80 files, so they are only read once and then shared.
	 */
	public static synchronized FdFunctionsInLibs getInstance() {
		if (instance == null || instance.libsList.isEmpty()) {
			// An empty result (tables could not be read) is not kept, so the next call tries again
			instance = new FdFunctionsInLibs();
		}
		return instance;
	}
	
	public FdFunctionsInLibs() {
		initList();
	}
	
	public String[] getLibsList(List<String> filter) {
		if (filter == null || filter.size() == 0) {
			return libsList.toArray(String[]::new);
		} else {
			return libsList.stream().filter(e -> filter.contains(e.toLowerCase())).toArray(String[]::new);
		}
	}
	
	public int findLibIndex(String lib) {
		return libsList.indexOf(lib);
	}
	
	public FdFunction[] getLibsFunctionsByBias(List<String> filter, int bias) {
		if (filter == null || filter.size() == 0) {
			return funcsList.stream().filter(e -> e.getBias() == bias).toArray(FdFunction[]::new);
		} else {
			return funcsList.stream().filter(e -> (filter.contains(e.getLib().toLowerCase()) && e.getBias() == bias)).toArray(FdFunction[]::new);
		}
	}
	
	public FdFunction[] getFunctionsByLibs(List<String> filter) {
		if (filter == null || filter.size() == 0) {
			return funcsList.toArray(FdFunction[]::new);
		} else {
			return funcsList.stream().filter(e -> filter.contains(e.getLib().toLowerCase())).toArray(FdFunction[]::new);
		}
	}
	
	public FdLibFunctions getFunctionTableByLib(String lib) {
		return libFuncs.stream().filter(e -> e.getKey().equals(lib)).map(e -> e.getValue()).findFirst().orElse(null);
	}
}
