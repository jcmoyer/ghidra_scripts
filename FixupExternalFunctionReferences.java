/**
 * Copyright (c) 2022 J.C. Moyer
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

// Fixes up external function references so they point at labels in an external
// program instead of whatever value they have on disk. Useful when a library is
// newer than an executable dynamically linking against it. If the executable's
// IAT is out of date, Ghidra will resolve incorrect external function addresses
// using on-disk bytes causing navigation to those functions to fail.
//@author J.C. Moyer
//@category Functions
import java.util.ArrayList;
import java.util.HashMap;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Symbol;

public class FixupExternalFunctionReferences extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Program baseProgram = askProgram("Choose base program");
        Program extProgram = askProgram("Choose external program");

        FunctionManager funcMan = baseProgram.getFunctionManager();
        FunctionIterator funcs = funcMan.getExternalFunctions();

        int totalResolvable = 0;
        int totalAmbiguous = 0;

        var extAddressMap = new HashMap<ExternalLocation, Address>();

        while (funcs.hasNext()) {
            Function func = funcs.next();
            ExternalLocation extLoc = func.getExternalLocation();

            var extSymsForLoc = extProgram.getSymbolTable().getSymbols(extLoc.getLabel());
            var candidates = new ArrayList<Symbol>();
            while (extSymsForLoc.hasNext()) {
                candidates.add(extSymsForLoc.next());
            }
            if (candidates.size() == 1) {
                var extAddr = candidates.get(0).getAddress();
                printf("unambigous: %s@%s can remap to %s\n", extLoc.getLabel(), extLoc.getAddress().toString(),
                        extAddr.toString());
                ++totalResolvable;

                extAddressMap.put(extLoc, extAddr);
            } else {
                printf("ambigous: %s has %d corresponding syms\n", extLoc.getLabel(), candidates.size());
                ++totalAmbiguous;
            }
        }

        printf("%d resolvable, %d ambiguous\n", totalResolvable, totalAmbiguous);

        var t = baseProgram.startTransaction("fixup external function references");
        boolean success = false;
        try {
            for (var extLoc : extAddressMap.keySet()) {
                var resolveAddr = extAddressMap.get(extLoc);
                extLoc.setAddress(resolveAddr);
            }
            success = true;
        } finally {
            baseProgram.endTransaction(t, success);
        }
    }
}
