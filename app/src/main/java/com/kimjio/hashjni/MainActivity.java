package com.kimjio.hashjni;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import com.kimjio.hash.HashTool;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";

    static {
        System.loadLibrary("hash");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        TextView tv = findViewById(R.id.sample_text);
        tv.setText(getStr(HashTool.getHashBytes("1234", "12345678")));

        Log.d(TAG, "onCreate: " + getStr(HashTool.getHashBytes("1234", "12345678")));
    }

    private static String getStr(int[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (int b : bytes) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }
}
