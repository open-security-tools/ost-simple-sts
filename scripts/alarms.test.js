"use strict";
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { resolve } = require("node:path");
const test = require("node:test");

test("alarms and dependency metrics exist without a notification topic", () => {
  const template = readFileSync(resolve(__dirname, "../template.yaml"), "utf8");
  const resources = template.split(/(?=^  [A-Za-z][A-Za-z0-9]*:\n)/m);
  const alarms = resources.filter((block) => block.includes("Type: AWS::CloudWatch::Alarm"));
  assert.equal(alarms.length, 5);
  for (const alarm of alarms) {
    assert.doesNotMatch(alarm, /^    Condition:/m);
    assert.match(alarm, /AlarmActions: !If \[HasAlarmTopic, \[!Ref AlarmTopicArn\], !Ref 'AWS::NoValue'\]/);
  }
  const metric = resources.find((block) => block.includes("Type: AWS::Logs::MetricFilter"));
  assert.ok(metric);
  assert.doesNotMatch(metric, /^    Condition:/m);
});
