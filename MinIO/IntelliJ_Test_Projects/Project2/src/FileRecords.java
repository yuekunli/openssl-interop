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

public class FileRecords {

    public class ObjectInfo {
        public String name;
        public boolean isBigOrSmall;

        public ObjectInfo(String _name, boolean _isBig)
        {
            name = _name;
            isBigOrSmall = _isBig;
        }
    }

    public class Bucket {
        public String name;
        public int objectCount;
        public int bigObjectTotal;
        public final int capacity = 20;
        public ObjectInfo[] objects = new ObjectInfo[capacity];

        private final String bigFilePath = "C:\\Users\\YuekunLi\\Downloads\\aws-java-sdk-1.12.350.zip";
        private final String smallFilePath = "C:\\Users\\YuekunLi\\text_file_2.txt";

        public Bucket(String _name)
        {
            name = _name;
            objectCount = 0;
            bigObjectTotal = 0;
        }

        public int getRandomObjectIndex()
        {
            int i = ran.nextInt(capacity);
            int k = 1; int index = 0;
            for (k = 1; k <= capacity; k++) {
                index = i % capacity;
                if (objects[index]!= null) {
                    break;
                }
                else
                {
                    i++;
                    k++;
                }
            }

            if (k > capacity)
                return -1;

            return index;
        }

        public String getObjectName(int index)
        {
            return objects[index].name;
        }

        public boolean canUploadObject()
        {
            return objectCount < capacity;
        }

        public void uploadObject(String name, int index, boolean bigOrSmall)
        {
            objects[index] = new ObjectInfo(name, bigOrSmall);
        }
        public void deleteObject(int index)
        {
            objects[index] = null;
        }

        public int getEmptySpotIndex()
        {
            int i = ran.nextInt(capacity);
            int k = 1; int index = 0;
            for (k = 1; k <= capacity; k++) {
                index = i % capacity;
                if (objects[index] == null) {
                    break;
                }
                else
                {
                    i++;
                    k++;
                }
            }

            if (k > capacity)
                return -1;

            return index;
        }
    }

    Random ran;
    private final int capacity = 10;
    public Bucket[] buckets = new Bucket[capacity];
    public int bigObjectTotal;
    public int smallObjectTotal;
    public int bucketCount;

    public FileRecords(Random _randomGenerator)
    {
        ran = _randomGenerator;
        bigObjectTotal = 0;
        smallObjectTotal = 0;
    }

    public int getRandomNonEmptyBucketIndex()
    {
        int i = ran.nextInt(capacity);
        int k = 1; int index = 0;
        for (k = 1; k <= capacity; k++) {
            index = i % capacity;
            if (buckets[index] != null && buckets[index].objectCount > 0) {
                break;
            }
            else
            {
                i++;
                k++;
            }
        }

        if (k > capacity)
            return -1;

        return index;
    }

    public int getRandomBucketIndex()
    {
        int i = ran.nextInt(capacity);
        int k = 1; int index = 0;
        for (k = 1; k <= capacity; k++) {
            index = i % capacity;
            if (buckets[index] != null) {
                break;
            }
            else
            {
                i++;
                k++;
            }
        }

        if (k > capacity)
            return -1;

        return index;
    }

    public void createBucket(String bucketName, int index)
    {
        buckets[index] = new Bucket(bucketName);
    }

    public void deleteBucket(int index)
    {
        buckets[index] = null;
    }

    public boolean canCreateBucket()
    {
        return bucketCount < capacity;
    }

    public int getEmptyBucketIndex()
    {
        int i = ran.nextInt(capacity);
        int k = 1; int index = 0;
        for (k = 1; k <= capacity; k++) {
            index = i % capacity;
            if (buckets[index]!= null && buckets[index].objectCount==0) {
                break;
            }
            else
            {
                i++;
                k++;
            }
        }

        if (k > capacity)
            return -1;

        return index;
    }

    public int getEmptySpotIndex()
    {
        int i = ran.nextInt(capacity);
        int k = 1; int index = 0;
        for (k = 1; k <= capacity; k++) {
            index = i % capacity;
            if (buckets[index] != null) {
                i++;
                k++;
            }
            else
                break;
        }

        if (k > capacity)
            return -1;

        return index;
    }

    public String getBucketName(int index)
    {
        return buckets[index].name;
    }

    public boolean canUploadObject(int bucketIndex)
    {
        return buckets[bucketIndex].canUploadObject();
    }

    public void uploadObject(int bucketIndex, String objectName, int objectIndex, boolean isBig)
    {
        buckets[bucketIndex].uploadObject(objectName, objectIndex, isBig);
    }

    public int getEmptySpotInBucket(int bucketIndex)
    {
        return buckets[bucketIndex].getEmptySpotIndex();
    }

    public int getObjectCountsInBucket(int bIndex)
    {
        return buckets[bIndex].objectCount;
    }
}
