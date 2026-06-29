#include <Arduino.h>
#include <Knot.h>

#include <cstring>

class PasswordStore {
 public:
	bool begin() {
		KnotConfig config;
		config.defaultCost = 4;
		KnotResult result = _knot.init(config);
		if (!result) {
			Serial.println(result.message);
			return false;
		}
		return true;
	}

	bool setPassword(const char *password) {
		KnotHashResult hash = _knot.hash(password);
		if (!hash) {
			Serial.println(hash.message);
			return false;
		}

		strncpy(_storedHash, hash.value, sizeof(_storedHash) - 1);
		_storedHash[sizeof(_storedHash) - 1] = '\0';
		return true;
	}

	bool verify(const char *password) {
		KnotCompareResult check = _knot.compare(password, _storedHash);
		if (!check) {
			Serial.println(check.message);
			return false;
		}
		return check.match;
	}

  private:
	Knot _knot;
	char _storedHash[KNOT_MAX_HASH_LENGTH + 1] = {};
};

PasswordStore passwords;

void setup() {
	Serial.begin(115200);

	if (!passwords.begin()) {
		return;
	}
	if (!passwords.setPassword("panel-secret")) {
		return;
	}

	Serial.println(passwords.verify("panel-secret") ? "valid" : "invalid");
}

void loop() {
	delay(1000);
}
