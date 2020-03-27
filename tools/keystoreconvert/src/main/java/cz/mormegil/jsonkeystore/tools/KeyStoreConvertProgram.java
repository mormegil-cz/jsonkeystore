package cz.mormegil.jsonkeystore.tools;

import cz.mormegil.jsonkeystore.JsonKeyStoreProvider;
import picocli.CommandLine;

import java.io.File;
import java.util.concurrent.Callable;

/**
 * The command-line driver program for the keystore convertor.
 *
 * @see KeyStoreConvertor
 */
@CommandLine.Command(name = "keystoreconvert", mixinStandardHelpOptions = true, version = "jsonkeystore ${bundle:VERSION}",
        description = "Converts a Java keystore file between formats.", resourceBundle = "KeyStoreConvertProgram")
class KeyStoreConvertProgram implements Callable<Integer> {
    /**
     * Program entry point
     *
     * @param args Command-line arguments
     */
    public static void main(String... args) {
        JsonKeyStoreProvider.ensureRegistered();

        final int result = new CommandLine(new KeyStoreConvertProgram()).execute(args);
        System.exit(result);
    }

    @CommandLine.Option(names = {"-i", "--input-file"}, required = true, paramLabel = "FILENAME", description = "The input keystore file")
    File inputFile;

    @CommandLine.Option(names = {"-o", "--output-file"}, required = true, paramLabel = "FILENAME", description = "The output keystore file")
    File outputFile;

    @CommandLine.Option(names = {"-f", "--from-format"}, required = true, paramLabel = "FORMAT", description = "Format of the input keystore (JCEKS, JSONKS, ...)")
    String inputFormat;

    @CommandLine.Option(names = {"-t", "--to-format"}, required = true, paramLabel = "FORMAT", description = "Format of the output keystore (JCEKS, JSONKS, ...)")
    String outputFormat;

    @CommandLine.Option(names = {"--storepass"}, arity = "0..1", interactive = true, paramLabel = "PASSWORD", description = "Keystore password to use", defaultValue = "")
    char[] storePassword;

    @CommandLine.Option(names = {"--keypass"}, arity = "0..1", interactive = true, paramLabel = "PASSWORD", description = "Key password to use", defaultValue = "")
    char[] keyPassword;

    /**
     * Execution of the program after parsing the command-line arguments
     *
     * @return Program error code
     * @throws Exception If any exception occurred
     */
    @Override
    public Integer call() throws Exception {
        new KeyStoreConvertor().convert(inputFile, inputFormat, outputFile, outputFormat, storePassword, keyPassword);
        return 0;
    }
}
