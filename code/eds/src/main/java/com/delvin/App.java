package com.delvin;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import com.delvin.printer.Printer;

public class App {
    public static void main(String... argv) {
        Args args = new Args();
        JCommander jc = JCommander.newBuilder().addObject(args).build();
        jc.setProgramName("eds");
        try {
            jc.parse(argv);
        } catch (ParameterException e) {
            e.usage();
            System.exit(1);
        }

        if (args.isHelp()) {
            jc.usage();
            System.exit(1);
        }

        Sign sign = new Sign(args);
        if (!args.checkKeySize()) {
            Printer.error(args.incorrectKeySize());
            System.exit(1);
        }

        if (args.getAlgorithm().equals("none")) {
            Printer.error(args.incorrectHash());
            jc.usage();
            System.exit(1);
        }

        if (args.getGenerateFlag()) {
            Printer.success("Generating a public/private key pair");
            sign.dumpKeyPair();
            System.exit(0);
        }

        if (!args.checkFileName()) {
            Printer.error("Please specify the file.");
            jc.usage();
            System.exit(1);
        }

        if (args.getMode().equals("none")) {
            Printer.error(args.incorrectMode());
            jc.usage();
            System.exit(1);
        }

        if (args.getMode().equals("sign")) {
            Printer.success("Start signing...");
            sign.createSign();
        } else {
            Printer.success("Check sign...");
            sign.checkSign();
        }

        Printer.success("Done");
    }
}
