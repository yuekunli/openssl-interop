import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.List;
import java.util.UUID;
import java.util.Random;

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.Bucket;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.ListObjectsRequest;
import com.amazonaws.services.s3.model.ObjectListing;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectSummary;
import com.amazonaws.services.s3.transfer.TransferManager;
import com.amazonaws.services.s3.transfer.TransferManagerBuilder;
import com.amazonaws.services.s3.transfer.Upload;
import com.amazonaws.services.s3.transfer.TransferProgress;

public class MinIOTestWorker implements Runnable {
    private String keyId;
    private String secretKey;
    private String minioServerIp = "http://127.0.0.1:9000";
    private String region = Regions.US_WEST_1.name();
    private AmazonS3 s3Client;
    private FileRecords fr;
    public Random ran;
    TransferManager tx;

    public enum BucketActions {
        CREATE,
        DELETE,
        LIST_OBJECTS
    }

    public enum ObjectActions {
        PUT,
        GET,
        XTRANSFER,
        DELETE,
        SET_POLICY
    }

    public MinIOTestWorker(String _keyId, String _secretKey)
    {
        keyId = _keyId;
        secretKey = _secretKey;
        ran = new Random();
        fr = new FileRecords(ran);
    }
    private void setup () {
        try {
            AWSCredentials credentials = new BasicAWSCredentials(keyId, secretKey);
            ClientConfiguration clientConfiguration = new ClientConfiguration();
            clientConfiguration.setSignerOverride("AWSS3V4SignerType");

            s3Client = AmazonS3ClientBuilder.standard()
                    .withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration(minioServerIp, region))
                    .withPathStyleAccessEnabled(true)
                    .withClientConfiguration(clientConfiguration)
                    .withCredentials(new AWSStaticCredentialsProvider(credentials))
                    .build();

            tx = TransferManagerBuilder.standard().withS3Client(s3Client).build();
            //tx.getAmazonS3Client().createBucket(bucketName);

        } catch (Exception e) {
            System.out.println("Exception when building S3 Client");
            System.out.println(e.getMessage());
        }
    }
    private void createBucket()
    {
        if (fr.canCreateBucket()) {
            int index = fr.getEmptySpotIndex();
            if (index >= 0) {
                String name = UUID.randomUUID().toString();
                s3Client.createBucket(name);
                fr.createBucket(name, index);
            }
        }
    }
    private void deleteBucket()
    {
        int index = fr.getEmptyBucketIndex();
        if (index >= 0) {
            String name = fr.getBucketName(index);
            s3Client.deleteBucket(name);
            fr.deleteBucket(index);
        }
    }

    private void listObjectsInBucket() {
        // what is the bucket count in the internal record
        int index = fr.getRandomNonEmptyBucketIndex();
        int internalCount = fr.getObjectCountsInBucket(index);
        String bName = fr.getBucketName(index);

        ObjectListing objectListing = s3Client.listObjects(new ListObjectsRequest().withBucketName(bName));
        if (internalCount != objectListing.getObjectSummaries().size()) {
            throw new RuntimeException();
        }
    }

    private void pubObject(boolean isBig)
    {

    }

    private void getObject()
    {

    }

    private void transferObject()
    {

    }

    private void deleteObject()
    {

    }

    private void setPolicyOnObject()
    {

    }

    @Override
    public void run()
    {
        setup();

        int i = 0;
        while (i < 100) {

            int bucketOrObject = ran.nextInt(2);

            if (bucketOrObject == 0) {
                BucketActions op = BucketActions.values()[ran.nextInt(3)];
                switch (op) {
                    case CREATE:
                        createBucket();
                        break;
                    case DELETE:
                        deleteBucket();
                        break;
                    case LIST_OBJECTS:
                        listObjectsInBucket();
                        break;
                }
            } else {
                ObjectActions op = ObjectActions.values()[ran.nextInt(5)];
                switch (op) {
                    case PUT:
                        int bigOrSmall = ran.nextInt(2);
                        pubObject(bigOrSmall == 0);
                        break;
                    case GET:
                        getObject();
                        break;
                    case XTRANSFER:
                        transferObject();
                        break;
                    case DELETE:
                        deleteObject();
                        break;
                    case SET_POLICY:
                        setPolicyOnObject();
                        break;
                }
            }

            i++;
        }
    }
}
