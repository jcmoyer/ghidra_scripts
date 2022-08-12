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
package jcmoyer.ghidra_scripts;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class LabelSet {
    private List<Label> labels;
    private Set<Long> addresses;

    public LabelSet() {
        labels = new ArrayList<>();
        addresses = new HashSet<>();
    }

    public void add(Label label) {
        if (addresses.contains(label.getAddress())) {
            throw new RuntimeException("duplicate address");
        }
        addresses.add(label.getAddress());
        labels.add(label);
    }

    public void sortByAddress() {
        labels.sort((a, b) -> Long.compare(a.getAddress(), b.getAddress()));
    }

    public void loadFromCsv(BufferedReader reader) {
        //@formatter:off
        reader.lines()
              .map(line -> line.split(","))
              .map(cols -> new Label(Long.parseLong(cols[0], 16), cols[1]))
              .forEach(label -> add(label));
        //@formatter:on
    }

    public void saveToCsv(BufferedWriter writer) {
        for (Label label : labels) {
            try (PrintWriter pw = new PrintWriter(writer)) {
                pw.format("%x,%s", label.getAddress(), label.getName());
            }
        }
    }

    public List<Label> getLabels() {
        return Collections.unmodifiableList(labels);
    }
}
