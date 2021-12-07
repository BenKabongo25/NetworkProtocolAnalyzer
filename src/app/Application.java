package app;

import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class Application extends javafx.application.Application {

    public final String APPLICATION_NAME = "Network Protocol Analyzer";

    private Stage stage;

    @Override
    public void start(Stage primaryStage) throws Exception {
        this.stage = primaryStage;
        primaryStage.setTitle(APPLICATION_NAME);

        FXMLLoader loader = new FXMLLoader(getClass().getResource("principal.fxml"));
        Parent root = loader.load();
        PrincipalController principalController = loader.getController();
        principalController.init(this);

        Scene scene = new Scene(root, 800, 600);
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    public Stage getStage() {
        return stage;
    }
}
