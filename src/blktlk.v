module main

import blkdb 
import os
import json
import time
import crypto.bcrypt

__global (
	messages blkdb.Table
	users blkdb.Table
)

fn read() {
	if os.exists("messages.blkdb") {
		messages=json.decode(blkdb.Table, os.read_file("messages.blkdb") or { return }) or { return }
	} else {
		messages=blkdb.Table.init("messages", ["content", "sender", "timestamp"])
	}

	if os.exists("users.blkdb") {
		users=json.decode(blkdb.Table, os.read_file("users.blkdb") or { return }) or { return }
	} else {
		users=blkdb.Table.init("users", ["name", "regts", "passhash"])
	}
}

fn write() {
	os.write_file("messages.blkdb", json.encode(messages)) or { panic(err) }
	os.write_file("users.blkdb", json.encode(users)) or { panic(err) }
}


fn new_user(name string, pubk string, password string) bool {
	if users.where("name",[name],"match").len!=0 {
		return false
	}
	users.insert({
		"name": name
		"passhash": json.encode(bcrypt.generate_from_password(password.bytes(), 5) or { return false }) 
		"regts": time.now().unix_time().str()
	})
	return true
}

fn auth(name string, password string) bool {
	res:=users.where("name", [name], "match")
	if res.len!=0 {
		return bcrypt.compare_hash_and_password(password.bytes(), res[0].data["password"].bytes()) or { return false }
	}
	return false
}