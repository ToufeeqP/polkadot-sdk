// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Unit tests for the non-fungible-token module.

#![cfg(test)]

use crate::{
	tests::substrate::mock::{dynamic_params::*, *},
	*,
};
use frame_support::{assert_noop, assert_ok, traits::AggregratedKeyValue};
use RuntimeOrigin as Origin;

#[docify::export]
#[test]
fn set_parameters_example() {
	use RuntimeParameters::*;

	new_test_ext().execute_with(|| {
		assert_eq!(pallet1::Key3::get(), 2, "Default works");

		// This gets rejected since the origin is not root.
		assert_noop!(
			ModuleParameters::set_parameter(
				Origin::signed(1),
				Pallet1(pallet1::Parameters::Key3(pallet1::Key3, Some(123))),
			),
			DispatchError::BadOrigin
		);

		assert_ok!(ModuleParameters::set_parameter(
			Origin::root(),
			Pallet1(pallet1::Parameters::Key3(pallet1::Key3, Some(123))),
		));

		assert_eq!(pallet1::Key3::get(), 123, "Update works");
	});
}

#[test]
fn set_parameters() {
	/*new_test_ext().execute_with(|| {
		assert_eq!(
			<ModuleParameters as RuntimeParameterStore>::get::<pallet1::Parameters, _>(
				pallet1::Key1
			),
			None
		);

		assert_noop!(
			ModuleParameters::set_parameter(
				RuntimeOrigin::signed(1),
				RuntimeParameters::Pallet1(pallet1::Parameters::Key1(pallet1::Key1, Some(123))),
			),
			DispatchError::BadOrigin
		);

		assert_ok!(ModuleParameters::set_parameter(
			RuntimeOrigin::root(),
			RuntimeParameters::Pallet1(pallet1::Parameters::Key1(pallet1::Key1, Some(123))),
		));

		assert_eq!(
			<ModuleParameters as RuntimeParameterStore>::get::<pallet1::Parameters, _>(
				pallet1::Key1
			),
			Some(123)
		);

		assert_ok!(ModuleParameters::set_parameter(
			RuntimeOrigin::root(),
			RuntimeParameters::Pallet1(pallet1::Parameters::Key2(pallet1::Key2(234), Some(345))),
		));

		assert_eq!(
			<ModuleParameters as RuntimeParameterStore>::get::<pallet1::Parameters, _>(
				pallet1::Key2(234)
			),
			Some(345)
		);

		assert_eq!(
			<ModuleParameters as RuntimeParameterStore>::get::<pallet1::Parameters, _>(
				pallet1::Key2(235)
			),
			None
		);

		assert_eq!(
			<ModuleParameters as RuntimeParameterStore>::get::<pallet2::Parameters, _>(
				pallet2::Key3((1, 2))
			),
			None
		);

		assert_noop!(
			ModuleParameters::set_parameter(
				RuntimeOrigin::root(),
				RuntimeParameters::Pallet2(pallet2::Parameters::Key3(
					pallet2::Key3((1, 2)),
					Some(123)
				)),
			),
			DispatchError::BadOrigin
		);

		assert_ok!(ModuleParameters::set_parameter(
			RuntimeOrigin::signed(1),
			RuntimeParameters::Pallet2(pallet2::Parameters::Key3(pallet2::Key3((1, 2)), Some(456))),
		));

		assert_eq!(
			<ModuleParameters as RuntimeParameterStore>::get::<pallet2::Parameters, _>(
				pallet2::Key3((1, 2))
			),
			Some(456)
		);
	});*/
}

#[test]
fn test_define_parameters_key_convert() {
	let key1 = pallet1::Key1;
	let parameter_key: pallet1::ParametersKey = key1.clone().into();
	let key1_2: pallet1::Key1 = parameter_key.clone().try_into().unwrap();

	assert_eq!(key1, key1_2);
	assert_eq!(parameter_key, pallet1::ParametersKey::Key1(key1));

	let key2 = pallet1::Key2;
	let parameter_key: pallet1::ParametersKey = key2.clone().into();
	let key2_2: pallet1::Key2 = parameter_key.clone().try_into().unwrap();

	assert_eq!(key2, key2_2);
	assert_eq!(parameter_key, pallet1::ParametersKey::Key2(key2));
}

#[test]
fn test_define_parameters_value_convert() {
	let value1 = pallet1::Key1Value(1);
	let parameter_value: pallet1::ParametersValue = value1.clone().into();
	let value1_2: pallet1::Key1Value = parameter_value.clone().try_into().unwrap();

	assert_eq!(value1, value1_2);
	assert_eq!(parameter_value, pallet1::ParametersValue::Key1(1));

	let value2 = pallet1::Key2Value(2);
	let parameter_value: pallet1::ParametersValue = value2.clone().into();
	let value2_2: pallet1::Key2Value = parameter_value.clone().try_into().unwrap();

	assert_eq!(value2, value2_2);
	assert_eq!(parameter_value, pallet1::ParametersValue::Key2(2));
}

#[test]
fn test_define_parameters_aggregrated_key_value() {
	let kv1 = pallet1::Parameters::Key1(pallet1::Key1, None);
	let (key1, value1) = kv1.clone().into_parts();

	assert_eq!(key1, pallet1::ParametersKey::Key1(pallet1::Key1));
	assert_eq!(value1, None);

	let kv2 = pallet1::Parameters::Key2(pallet1::Key2, Some(2));
	let (key2, value2) = kv2.clone().into_parts();

	assert_eq!(key2, pallet1::ParametersKey::Key2(pallet1::Key2));
	assert_eq!(value2, Some(pallet1::ParametersValue::Key2(2)));
}

#[test]
fn test_define_aggregrated_parameters_key_convert() {
	use codec::Encode;

	let key1 = pallet1::Key1;
	let parameter_key: pallet1::ParametersKey = key1.clone().into();
	let runtime_key: RuntimeParametersKey = parameter_key.clone().into();

	assert_eq!(runtime_key, RuntimeParametersKey::Pallet1(pallet1::ParametersKey::Key1(key1)));
	assert_eq!(runtime_key.encode(), vec![0, 0]);

	let key2 = pallet2::Key2;
	let parameter_key: pallet2::ParametersKey = key2.clone().into();
	let runtime_key: RuntimeParametersKey = parameter_key.clone().into();

	assert_eq!(runtime_key, RuntimeParametersKey::Pallet2(pallet2::ParametersKey::Key2(key2)));
	assert_eq!(runtime_key.encode(), vec![1, 1]);
}

#[test]
fn test_define_aggregrated_parameters_aggregrated_key_value() {
	let kv1 = RuntimeParameters::Pallet1(pallet1::Parameters::Key1(pallet1::Key1, None));
	let (key1, value1) = kv1.clone().into_parts();

	assert_eq!(key1, RuntimeParametersKey::Pallet1(pallet1::ParametersKey::Key1(pallet1::Key1)));
	assert_eq!(value1, None);

	let kv2 = RuntimeParameters::Pallet2(pallet2::Parameters::Key2(pallet2::Key2, Some(2)));
	let (key2, value2) = kv2.clone().into_parts();

	assert_eq!(key2, RuntimeParametersKey::Pallet2(pallet2::ParametersKey::Key2(pallet2::Key2)));
	assert_eq!(value2, Some(RuntimeParametersValue::Pallet2(pallet2::ParametersValue::Key2(2))));
}
