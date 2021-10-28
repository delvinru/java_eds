package com.delvin.printer;

public class Printer {
    public static void success(String msg) {
        System.out.println(ConsoleColors.GREEN + "[+] " + msg + ConsoleColors.RESET);
    }

    public static void error(String msg) {
        System.out.println(ConsoleColors.RED + "[-] " + msg + ConsoleColors.RESET);
    }

    public static void warning(String msg) {
        System.out.println(ConsoleColors.YELLOW + "[!] " + msg + ConsoleColors.RESET);
    }

    public static void info(String msg) {
        System.out.println("[+] " + msg);
    }
}
