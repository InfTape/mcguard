package com.mcguard.testmod;

import net.fabricmc.api.ModInitializer;
import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.command.v2.ClientCommandManager;
import net.fabricmc.fabric.api.client.command.v2.ClientCommandRegistrationCallback;
import net.fabricmc.fabric.api.client.command.v2.FabricClientCommandSource;
import com.mojang.brigadier.arguments.StringArgumentType;
import net.minecraft.class_2561;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class TestMod implements ModInitializer, ClientModInitializer {

    @Override
    public void onInitialize() {
        System.out.println("[MCGuard-TestMod] Mod initialized. Client command /r will be registered on client.");
    }

    @Override
    public void onInitializeClient() {
        System.out.println("[MCGuard-TestMod] Registering /r client command...");
        ClientCommandRegistrationCallback.EVENT.register((dispatcher, registryAccess) -> {
            dispatcher.register(
                ClientCommandManager.literal("r")
                    .executes(context -> {
                        send(context.getSource(), "§e[MCGuard-Test] 用法: /r <文件或目录路径>");
                        send(context.getSource(), "§7例如: /r %USERPROFILE%\\.ssh");
                        send(context.getSource(), "§7例如: /r %USERPROFILE%\\Desktop\\test.txt");
                        send(context.getSource(), "§7例如: /r %APPDATA%\\.hmcl\\private\\user-account-private-data.json");
                        return 1;
                    })
                    .then(ClientCommandManager.argument("path", StringArgumentType.greedyString())
                        .executes(context -> {
                            String rawPath = StringArgumentType.getString(context, "path");
                            testPathAccess(context.getSource(), rawPath);
                            return 1;
                        })
                    )
            );
        });
        System.out.println("[MCGuard-TestMod] /r command registered successfully!");
    }

    private static void send(FabricClientCommandSource source, String msg) {
        System.out.println("[MCGuard-TestMod] " + msg);
        try {
            source.sendFeedback(class_2561.method_43470(msg));
        } catch (Throwable t) {
            System.err.println("[MCGuard-TestMod] Failed to send chat message: " + t);
        }
    }

    private static String expandPath(String path) {
        if (path == null) return "";
        path = path.trim();
        if (path.startsWith("\"") && path.endsWith("\"") && path.length() >= 2) {
            path = path.substring(1, path.length() - 1).trim();
        }
        String userHome = System.getProperty("user.home", "");
        if (path.startsWith("~\\") || path.startsWith("~/")) {
            path = userHome + File.separator + path.substring(2);
        } else if (path.equals("~")) {
            path = userHome;
        }
        if (path.contains("%")) {
            for (Map.Entry<String, String> entry : System.getenv().entrySet()) {
                String key = "%" + entry.getKey() + "%";
                if (path.toLowerCase().contains(key.toLowerCase())) {
                    path = path.replaceAll("(?i)" + Pattern.quote(key), Matcher.quoteReplacement(entry.getValue()));
                }
            }
        }
        return path;
    }

    private static void testPathAccess(FabricClientCommandSource source, String rawPath) {
        String resolvedPath = expandPath(rawPath);
        File target = new File(resolvedPath);
        String absPath = target.getAbsolutePath();

        send(source, "§6════════════════════════════════════════════");
        send(source, "§e[MCGuard-Test] 测试目标: §f" + absPath);

        boolean exists = false;
        boolean isDir = false;
        try {
            exists = target.exists();
            isDir = target.isDirectory();
            if (exists) {
                send(source, "§7[状态] 目标存在: " + (isDir ? "文件夹 (Directory)" : "文件 (大小: " + target.length() + " 字节)"));
            } else {
                send(source, "§7[状态] target.exists() = false (不存在或已被内核阻断)");
            }
        } catch (Throwable t) {
            send(source, "§a[已成功阻断 - BLOCK] exists() 查询被内核拦截: " + t.getClass().getSimpleName());
        }

        // 1. 测试读 / 列出目录 (Read / List Access)
        send(source, "§e[1. 读取测试] 尝试读取 / 遍历目标...");
        try {
            if (isDir) {
                File[] list = target.listFiles();
                if (list != null) {
                    send(source, "§c[未阻断 - ALLOWED] 目录遍历成功! 发现 " + list.length + " 个子项 (沙箱未拦截)");
                } else {
                    send(source, "§a[已成功阻断 - BLOCK] listFiles() 返回 NULL (读权限被沙箱拒绝!)");
                }
            } else {
                byte[] data = Files.readAllBytes(target.toPath());
                send(source, "§c[未阻断 - ALLOWED] 文件读取成功! 读取了 " + data.length + " 字节 (沙箱未拦截)");
            }
        } catch (Throwable t) {
            send(source, "§a[已成功阻断 - BLOCK] 读取抛出异常: " + t.getClass().getSimpleName() + " (" + t.getMessage() + ")");
        }

        // 2. 测试写 / 创建文件 (Write / Create Access)
        send(source, "§e[2. 写入测试] 尝试在目标处写入测试数据...");
        try {
            if (isDir) {
                File testFile = new File(target, ".mcguard_write_probe_" + System.currentTimeMillis() + ".tmp");
                Files.writeString(testFile.toPath(), "MCGuard sandbox write probe");
                testFile.delete(); // 清理测试文件
                send(source, "§c[未阻断 - ALLOWED] 写入测试成功! 允许在目标目录创建文件 (沙箱未拦截)");
            } else {
                try (FileOutputStream fos = new FileOutputStream(target, true)) {
                    fos.write(new byte[0]); // 尝试以追加模式打开并写0字节
                }
                send(source, "§c[未阻断 - ALLOWED] 文件写入句柄获取成功! (沙箱未拦截)");
            }
        } catch (Throwable t) {
            send(source, "§a[已成功阻断 - BLOCK] 写入抛出异常: " + t.getClass().getSimpleName() + " (" + t.getMessage() + ")");
        }

        send(source, "§6════════════════════════════════════════════");
    }
}
