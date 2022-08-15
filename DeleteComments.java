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

// Deletes comments matching a regular expression.
//@author J.C. Moyer
//@category Cleanup

import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;

public class DeleteComments extends GhidraScript {
    //@formatter:off
    private static final Map<String, Integer> COMMENT_TYPE_MAP = Map.ofEntries(
        Map.entry("EOL", CodeUnit.EOL_COMMENT),
        Map.entry("PRE", CodeUnit.PRE_COMMENT),
        Map.entry("POST", CodeUnit.POST_COMMENT),
        Map.entry("PLATE", CodeUnit.PLATE_COMMENT),
        Map.entry("REPEATABLE", CodeUnit.REPEATABLE_COMMENT)
    );
    //@formatter:on

    @Override
    public void run() throws Exception {
        String regexStr = askString("Delete Comments", "Enter a regex");
        Pattern regexPat = Pattern.compile(regexStr);

        List<String> choices = COMMENT_TYPE_MAP.keySet().stream().collect(Collectors.toList());
        List<String> picked = askChoices("Delete Comments", "Which types of comments should be deleted?", choices);
        List<Integer> pickedIndices = picked.stream().map(COMMENT_TYPE_MAP::get).collect(Collectors.toList());

        Program prog = getCurrentProgram();
        Listing listing = prog.getListing();
        Memory memory = prog.getMemory();

        int deleteCount = 0;

        int transaction = prog.startTransaction("Delete Comments");
        boolean success = false;

        try {
            AddressIterator addressIter = listing.getCommentAddressIterator(memory, true);
            while (addressIter.hasNext()) {
                Address addr = addressIter.next();
                for (int i = 0; i < pickedIndices.size(); ++i) {
                    String comment = listing.getComment(i, addr);

                    if (comment == null) {
                        continue;
                    }

                    Matcher matcher = regexPat.matcher(comment);
                    if (matcher.find()) {
                        listing.setComment(addr, i, null);
                        ++deleteCount;
                    }
                }
            }
            success = true;
        } finally {
            prog.endTransaction(transaction, success);
        }

        printf("deleted %d comments\n", deleteCount);
    }
}
