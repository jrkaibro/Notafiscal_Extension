package com.knetapp.systray;

import com.knetapp.service.nfeServerPublisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

public class nfeSystemTray {

	static Logger logger = LoggerFactory.getLogger(nfeSystemTray.class);
	static String appdata = System.getenv("APPDATA").replace("\\","\\\\");

	public static void main(String[] args) {

		System.out.println("Path: " + appdata);

		for (Thread t : Thread.getAllStackTraces().keySet()) {
			if (t.getName().equals("wvetro")) {
				System.out.println(t.getName() + " So ID: " + t.getId());
				t.stop();
			}
		}

		nfeSystemTray.logger.warn("Create registry windows...");
		nfeSystemTray.create_registry();
		nfeSystemTray.logger.info("waiting 1 seconds....");

		Thread wvetro = new Thread(new wvetroRun(), "wvetro");
		nfeSystemTray.logger.info("Starting....");

		wvetro.start();
	}

	private static void create_registry() {

		final StringBuilder registry = new StringBuilder();
		registry.append("Windows Registry Editor Version 5.00")
				.append("\n\n")
				.append("[HKEY_CURRENT_USER\\SOFTWARE\\Google\\Chrome\\NativeMessagingHosts\\com.knetapp.native]")
				.append("\n")
				.append("@=\"")
				.append(appdata)
				.append("\\\\wvetro\\\\com.knetapp.native.json\"");

		final StringBuffer str = new StringBuffer();
		str.append(registry);

		/*
		try {
			FileWriter out;
			out = new FileWriter(appdata + "\\\\wvetro\\\\wvetro.reg");
			out.write(str.toString());
			out.close();

		} catch (final IOException e) {
			e.printStackTrace();
		}
		*/

	}

}

class wvetroRun implements Runnable {

	public static String urlaccess() {

		int responseCode = 0;
		String retorno = null;

		try {

			final URL url = new URL("http://127.0.0.1:9876/com.knetapp.service.ServiceServer");
			final HttpURLConnection huc = (HttpURLConnection) url.openConnection();
			responseCode = huc.getResponseCode();

		} catch (final Exception e) {
			nfeSystemTray.logger.equals("error loading " + e.getMessage());
		}

		if (responseCode == 200) {
			retorno = "Service online";
		} else {
			retorno = "Service offline";
		}

		return retorno;
	}

	@Override
	public void run() {

		if (!SystemTray.isSupported()) {

			return;
		} else {

			String code = urlaccess();

			if (code.equals("Service offline")) {
				nfeServerPublisher server = new nfeServerPublisher();
				server.main();
			}

			SystemTray tray = SystemTray.getSystemTray();
			@SuppressWarnings("unused")
			Toolkit toolkit = Toolkit.getDefaultToolkit();
			Dimension trayIconSize = tray.getTrayIconSize();

			File folderInput = new File("resource//icon.png");

			Image image = null;
			try {
				image = ImageIO.read(folderInput);
				image = image.getScaledInstance(trayIconSize.width, trayIconSize.height, Image.SCALE_SMOOTH);
			} catch (IOException e) {
				e.printStackTrace();
			}

			PopupMenu menu = new PopupMenu();

			MenuItem messageItem = new MenuItem("Version");

			messageItem.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					JOptionPane.showMessageDialog(null, "1.0.0.2");
				}
			});

			menu.add(messageItem);

			MenuItem closeItem = new MenuItem("Sair");
			closeItem.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					System.exit(0);
				}
			});

			menu.add(closeItem);

			try {
				TrayIcon icon = new TrayIcon(image, "Service SmartCard.", menu);
				tray.add(icon);
			} catch (AWTException e) {
				e.printStackTrace();
			}

		}
	}




}
