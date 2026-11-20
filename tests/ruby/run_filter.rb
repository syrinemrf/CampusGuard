# Exécute le code « ruby { code => ... } » d'un pipeline Logstash sur des lignes, avec un faux objet event.
# Usage : ruby run_filter.rb <pipeline.conf> <id du filtre> < messages  → une ligne JSON par message
require 'json'
class FakeEvent
  def initialize(h) @h = h end
  def key(p) p.start_with?('[') ? p.scan(/\[([^\]]+)\]/).flatten : [p] end
  def get(p) key(p).reduce(@h) { |acc, k| acc.is_a?(Hash) ? acc[k] : nil } end
  def set(p, v)
    ks = key(p); last = ks.pop
    ks.reduce(@h) { |acc, k| acc[k] ||= {} }[last] = v
  end
  def tag(t) (@h['tags'] ||= []) << t end
  def to_h() @h end
end
conf = File.read(ARGV[0], encoding: 'UTF-8')
block = conf[/id => "#{ARGV[1]}"\s+code => "(.*?)"\s+tag_on_exception/m, 1] or abort 'filtre introuvable'
STDIN.each_line do |line|
  event = FakeEvent.new({ '@metadata' => { 'msg' => line.chomp, 'transport' => 'tcp' } })
  eval(block)
  h = event.to_h; h.delete('@metadata')
  puts JSON.generate(h)
end
