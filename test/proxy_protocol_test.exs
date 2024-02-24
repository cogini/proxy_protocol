defmodule ProxyProtocolTest do
  use ExUnit.Case
  doctest ProxyProtocol

  test "greets the world" do
    assert ProxyProtocol.hello() == :world
  end
end
