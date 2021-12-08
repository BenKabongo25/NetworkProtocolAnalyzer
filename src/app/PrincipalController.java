package app;

import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.control.Alert;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.Region;
import javafx.stage.FileChooser;
import model.analyzers.TracesAnalyzer;

import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class PrincipalController {

    @FXML
    private AnchorPane childPane;

    private Application application;
    private HomeController homeController;
    private Parent home;
    private MainController mainController;
    private Parent main;

    private boolean isMain;

    public void init(Application application) {
        this.application = application;

        try {
            FXMLLoader homeLoader = new FXMLLoader(getClass().getResource("home.fxml"));
            home = homeLoader.load();
            homeController = homeLoader.getController();
            homeController.init(this);
            FXMLLoader mainLoader = new FXMLLoader(getClass().getResource("main.fxml"));
            main = mainLoader.load();
            mainController = mainLoader.getController();
        } catch (Exception e) {
            e.printStackTrace();
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Error");
            alert.setHeaderText("Application launch error");
            alert.setContentText("The application could not be launched correctly!");
            alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
            alert.showAndWait();
        }

        setHome();
    }

    private void setHome() {
        isMain = false;
        application.getStage().setTitle(application.APPLICATION_NAME);
        AnchorPane.setLeftAnchor(home, 0.);
        AnchorPane.setTopAnchor(home, 0.);
        AnchorPane.setRightAnchor(home, 0.);
        AnchorPane.setBottomAnchor(home, 0.);
        childPane.getChildren().removeAll(home, main);
        childPane.getChildren().add(home);
    }

    private void setMain() {
        isMain = true;
        AnchorPane.setLeftAnchor(main, 0.);
        AnchorPane.setTopAnchor(main, 0.);
        AnchorPane.setRightAnchor(main, 0.);
        AnchorPane.setBottomAnchor(main, 0.);
        childPane.getChildren().removeAll(home, main);
        childPane.getChildren().add(main);
    }

    public void openFile(File file) {
        if (file == null)
            return;

        String content = "";
        try {
            Scanner scanner = new Scanner(file);
            while (scanner.hasNextLine())
                content += scanner.nextLine() + "\n";
            scanner.close();
        } catch (Exception e) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Opening error");
            alert.setHeaderText("Error opening or reading file");
            alert.setContentText("The selected file could not be opened or read correctly. Please choose another one.");
            alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
            alert.showAndWait();
            return;
        }

        if (content.isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Opening error");
            alert.setHeaderText("Empty or unreadable file");
            alert.setContentText("The selected file is empty or unreadable. Please choose another one.");
            alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
            alert.showAndWait();
            return;
        }

        application.getStage().setTitle(file + " - " + application.APPLICATION_NAME);
        TracesAnalyzer tracesAnalyzer = new TracesAnalyzer(content, true);
        mainController.setTracesAnalyzer(tracesAnalyzer);
        setMain();
    }

    @FXML
    public void handleOpen() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open");
        File file = fileChooser.showOpenDialog(application.getStage());
        if (file != null) openFile(file);
    }

    @FXML
    public void handleClose() {
        if (isMain) setHome();
    }

    @FXML
    public void handleExportJson() {
        if (isMain) {

        }
    }

    @FXML
    public void handleExportText() {
        if (!isMain) return;
        String analyze = mainController.getAnalyze();
        if (analyze == null) {
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("Export text");
            alert.setHeaderText("Select a frame");
            alert.setContentText("Please select the frame to export");
            alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
            alert.showAndWait();
            return;
        }
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Export text");
        File file = fileChooser.showSaveDialog((application.getStage()));
        if (file == null) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Export error");
            alert.setHeaderText("Analysis export error");
            alert.setContentText("The export file could not be opened");
            alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
            alert.showAndWait();
            return;
        }
        try {
            FileOutputStream stream = new FileOutputStream(file);
            stream.write(analyze.getBytes(StandardCharsets.UTF_8));
            stream.close();
        } catch (FileNotFoundException e) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Export error");
            alert.setHeaderText("Analysis export error");
            alert.setContentText("The export file could not be opened");
            alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
            alert.showAndWait();
            return;
        } catch (IOException e) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Export error");
            alert.setHeaderText("Analysis export error");
            alert.setContentText("Analysis could not be written to file");
            alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
            alert.showAndWait();
            return;
        }
    }

    @FXML
    public void handleQuit() {
        Platform.exit();
    }

    @FXML
    public void handleHelp() {
        File html = new File("ressources/html/index.html");
        try {
            Desktop.getDesktop().browse(html.toURI());
        } catch (Exception ignored) {
        }
    }

    public void handleAboutUs() {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("About us");
        alert.setHeaderText("Ben Kabongo & Souleymane Mbaye");
        alert.setContentText("Currently students at Sorbonne University.\n" +
                "This project was coded for the Networks teaching unit, in L3 informatics at Sorbonne University.\n" +
                "Contacts :\n" +
                "Ben Kabongo : kabongo.ben025@gmail.com\n" +
                "Souleymane Mbaye : mbayesouleymane99@gmail.com\n");
        alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
        alert.showAndWait();
    }
}
