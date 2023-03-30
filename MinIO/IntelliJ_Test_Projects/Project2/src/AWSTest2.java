import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AWSTest2 {
    private String[] keyIds = {"user1", "user2", "user3", "user4"};
    private String[] secretKeys = {"KnockOnDoor1", "KnockOnDoor2", "KnockOnDoor3", "KnockOnDoor4"};

    public void run()
    {
        ExecutorService executor = Executors.newFixedThreadPool(4);
        for (int i = 0; i < 4; i++)
        {
            executor.execute(new MinIOTestWorker(keyIds[i], secretKeys[i]));
        }
        executor.shutdown();
    }
}
