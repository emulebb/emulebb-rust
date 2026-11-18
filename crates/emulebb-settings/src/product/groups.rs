// One declaration generates complete values, saved modes, partial edits,
// metadata and key dispatch. Fields/defaults are never maintained separately.
macro_rules! setting_group {
    ($values:ident,$saved:ident,$partial:ident,$prefix:literal, {
        leaves { $($field:ident:$ty:ty = $default:expr => ($wire:literal,$rule:expr,$apply:ident,$unit:literal)),* $(,)? }
        branches { $($group:ident:($child:ident,$saved_child:ident,$partial_child:ident) => $group_wire:literal),* $(,)? }
    }) => {
        #[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $values { $(#[serde(rename=$wire)] pub $field:$ty,)* $(#[serde(rename=$group_wire)] pub $group:$child,)* }
        impl Default for $values { fn default()->Self { Self {$($field:$default,)* $($group:$child::default(),)*} } }
        #[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $saved { $(#[serde(rename=$wire)] pub $field:SavedValue<$ty>,)* $(#[serde(rename=$group_wire)] pub $group:$saved_child,)* }
        impl Default for $saved { fn default()->Self { Self::from_defaults(&$values::default()) } }
        #[derive(Debug,Clone,Default,PartialEq,Eq,Serialize,Deserialize)]
        #[serde(default,deny_unknown_fields)]
        pub struct $partial { $(#[serde(rename=$wire,skip_serializing_if="PartialValue::is_unchanged")] pub $field:PartialValue<$ty>,)* $(#[serde(rename=$group_wire)] pub $group:$partial_child,)* }
        impl $values {
            pub(super) fn append_specs(out:&mut Vec<SettingSpec>) {
                $(out.push(spec::<$ty>(concat!($prefix,".",$wire),$default,ApplyMode::$apply,$unit,$rule));)*
                $($child::append_specs(out);)*
            }
            pub(super) fn validate_fields(&self,issues:&mut Vec<ValidationIssue>) {
                $(validate_field(&self.$field,concat!($prefix,".",$wire),$rule,issues);)*
                $(self.$group.validate_fields(issues);)*
            }
        }
        impl $saved {
            pub(super) fn from_defaults(defaults:&$values)->Self { Self {$($field:SavedValue::from_default(&defaults.$field),)* $($group:$saved_child::from_defaults(&defaults.$group),)*} }
            pub(super) fn resolve_with(&mut self,defaults:&$values) { $(self.$field.resolve(&defaults.$field);)* $(self.$group.resolve_with(&defaults.$group);)* }
            pub fn values(&self)->$values { $values {$($field:self.$field.value.clone(),)* $($group:self.$group.values(),)*} }
            pub(super) fn apply_partial(&mut self,partial:&$partial,defaults:&$values) {
                $(if let PartialValue::Set(value)=&partial.$field { self.$field.set(value.clone(),&defaults.$field); })*
                $(self.$group.apply_partial(&partial.$group,&defaults.$group);)*
            }
            pub(super) fn reset_key(&mut self,key:&str,defaults:&$values)->bool {
                match key { $(concat!($prefix,".",$wire)=>{self.$field=SavedValue::from_default(&defaults.$field);return true;},)* _=>{} }
                $(if self.$group.reset_key(key,&defaults.$group) {return true;})* false
            }
            pub(super) fn set_key(&mut self,key:&str,value:&Value,defaults:&$values)->Result<bool,SettingsError> {
                match key { $(concat!($prefix,".",$wire)=>{
                    let value:$ty=serde_json::from_value(value.clone()).map_err(|_|SettingsError::InvalidValue)?;
                    self.$field.set(value,&defaults.$field); return Ok(true);
                },)* _=>{} }
                $(if self.$group.set_key(key,value,&defaults.$group)? {return Ok(true);})* Ok(false)
            }
        }
        impl $partial {
            pub(super) fn touched_keys(&self,out:&mut Vec<SettingKey>) {
                $(if !self.$field.is_unchanged() { out.push(SettingKey(concat!($prefix,".",$wire))); })*
                $(self.$group.touched_keys(out);)*
            }
        }
    }
}
