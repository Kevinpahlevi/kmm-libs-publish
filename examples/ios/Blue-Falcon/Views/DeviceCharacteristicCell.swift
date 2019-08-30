//
//  DeviceCharacteristicCell.swift
//  Blue-Falcon
//
//  Created by Andrew Reed on 28/08/2019.
//  Copyright © 2019 Andrew Reed. All rights reserved.
//

import Foundation
import SwiftUI

struct DeviceCharacteristicCell: View {

    @ObservedObject private var viewModel: DeviceCharacteristicCellViewModel

    init(viewModel: DeviceCharacteristicCellViewModel) {
        self.viewModel = viewModel
    }

    var body: some View {
        VStack(alignment: HorizontalAlignment.leading, spacing: 10) {
            VStack(alignment: HorizontalAlignment.leading, spacing: 10) {
                HStack {
                    Text("ID: ").bold()
                    Text(viewModel.id.uuidString)
                }
                if viewModel.characteristic.value != nil {
                    HStack {
                        Text("Value: ").bold()
                        Text(String(decoding: viewModel.characteristic.value ?? Data(), as: UTF8.self))
                    }
                }
            }.padding()
            HStack {
                Spacer()
                Text("Read")
                    .onTapGesture {
                        self.viewModel.readCharacteristicTapped(self.viewModel.characteristic)
                    }
                    .foregroundColor(Color.white)
                    .padding()
                    .background(Color.blue)
                    .cornerRadius(5)
                Text("Notify \(viewModel.notify.description)")
                    .onTapGesture {
                        self.viewModel.notifyCharacteristicTapped(self.viewModel.characteristic)
                    }
                    .foregroundColor(Color.white)
                    .padding()
                    .background(Color.purple)
                    .cornerRadius(5)

                Text("Write")
                    .onTapGesture {
                        self.viewModel.writeCharacteristicTapped(self.viewModel.characteristic)
                    }
                    .foregroundColor(Color.white)
                    .padding()
                    .background(Color.yellow)
                    .cornerRadius(5)
            }
        }
    }
}
