package wallet.testHelper;

import au.com.bytecode.opencsv.CSVReader;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.io.FileReader;
import java.util.List;

// (P1, H1, SN, B1, H2, IV, CS, H3)
public class CsvToJsonConverterForActivationData {
    public static void main(String[] args) {
        try(CSVReader readerFull = new CSVReader(new FileReader("freshFullTuplesForTonCard131020.csv"))) {
            List<String[]> fullTuples = readerFull.readAll();
            JSONArray array = new JSONArray();
            for(int i = 0; i < fullTuples.size(); i++) {
                JSONObject item = new JSONObject();
                item.put("P1", fullTuples.get(i)[0]);
                item.put("H1", fullTuples.get(i)[1]);
                item.put("SN", fullTuples.get(i)[2]);
                item.put("B1", fullTuples.get(i)[3]);
                item.put("H2", fullTuples.get(i)[4]);
                item.put("IV", fullTuples.get(i)[5]);
                item.put("CS", fullTuples.get(i)[6]);
                item.put("ECS", fullTuples.get(i)[7]);
                item.put("H3", fullTuples.get(i)[8]);
                array.add(item);
            }
            System.out.println(array.toJSONString());
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("");

        try(CSVReader readerFeitian = new CSVReader(new FileReader("freshFeitianTuplesForTonCard131020.csv"))) {
            List<String[]> feitianTuples = readerFeitian.readAll();
            JSONArray array = new JSONArray();
            for(int i = 0; i < feitianTuples.size(); i++) {
                JSONObject item = new JSONObject();
                item.put("B1", feitianTuples.get(i)[0]);
                item.put("SN", feitianTuples.get(i)[1]);
                item.put("ECS", feitianTuples.get(i)[2]);
                array.add(item);
            }
            System.out.println(array.toJSONString());
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
}
