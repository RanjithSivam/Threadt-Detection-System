package com.ranjith.threatdetection.util;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.mapdb.DataInput2;
import org.mapdb.DataOutput2;
import org.mapdb.serializer.GroupSerializerObjectArray;

import com.ranjith.threatdetection.model.ThreatSourceData;

public class ThreatSourceDataSerializer extends GroupSerializerObjectArray<ThreatSourceData>{

	@Override
	public void serialize(DataOutput2 out, ThreatSourceData value) throws IOException {
		out.writeInt(value.getReputation());
		out.writeUTF(value.getCategory().toString());
	}

	@Override
	public ThreatSourceData deserialize(DataInput2 input, int available) throws IOException {
		Integer reputation = input.readInt();
		JSONArray jsonArray = new JSONArray(input.readUTF());
		
		return new ThreatSourceData(reputation, jsonArray);
	}

}
