use probing_macros::EngineExtension;
use probing_engine::core::EngineError;
use probing_engine::core::EngineExtensionOption;
use probing_engine::core::EngineExtension;



#[test]
fn test_macro() {
    #[derive(Debug, EngineExtension)]
    struct TestExtension {
        /// describe managed_field_name1
        #[option(aliases = ["mfn1", "a"])]
        managed_field_name1: i32,

        /// describe managed_field_name2
        /// with multiline docstring
        #[option(name = "managed.field_name2", aliases = ["mfn2", "b"])]
        managed_field_name2: String,

        /// this is a unmanaged field
        unmanaged_field_name: i64,
    }

    impl TestExtension {
        fn set_managed_field_name1(&mut self, value: i32) -> Result<(), EngineError>{
            self.managed_field_name1 = value;
            Ok(())
        }

        fn set_managed_field_name2(&mut self, value: String) -> Result<(), EngineError>{
            self.managed_field_name2 = value;
            Ok(())
        }
    }

    let mut ext = TestExtension {
        managed_field_name1: 1,
        managed_field_name2: "a".to_string(),
        unmanaged_field_name: 3,
    };

    assert_eq!(ext.get("managed_field_name1").unwrap(), "1".to_string());
    assert_eq!(ext.get("mfn1").unwrap(), "1".to_string());
    assert_eq!(ext.get("a").unwrap(), "1".to_string());

    assert!(ext.get("managed_field_name2").is_err());
    assert_eq!(ext.get("managed.field_name2").unwrap(), "a".to_string());
    assert_eq!(ext.get("mfn2").unwrap(), "a".to_string());
    assert_eq!(ext.get("b").unwrap(), "a".to_string());

    assert_eq!(ext.set("managed_field_name1", "2").unwrap(), "1".to_string());
    assert_eq!(ext.set("mfn1", "3").unwrap(), "2".to_string());
    assert_eq!(ext.set("a", "4").unwrap(), "3".to_string());

    assert!(ext.set("managed_field_name2", "error").is_err());
    assert_eq!(ext.set("managed.field_name2", "b").unwrap(), "a".to_string());
    assert_eq!(ext.set("mfn2", "c").unwrap(), "b".to_string());
    assert_eq!(ext.set("b", "d").unwrap(), "c".to_string());

    let opts = ext.options();
    assert_eq!(opts.len(), 2);
    assert_eq!(opts[0].key, "managed_field_name1");
    assert_eq!(opts[0].value, Some("4".to_string()));
    assert_eq!(opts[0].help, "describe managed_field_name1");
    assert_eq!(opts[1].key, "managed.field_name2");
    assert_eq!(opts[1].value, Some("d".to_string()));
    assert_eq!(opts[1].help, "describe managed_field_name2\nwith multiline docstring");
}
